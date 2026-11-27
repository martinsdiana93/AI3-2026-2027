import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import express from 'express';
import { carregarConfiguracao, criarAutenticacao, enviarErro } from './autenticacao.js';

const PORTA = process.env.PORT ?? 3000;
const PADRAO_UTILIZADOR = /^([0-9]{5,8}|[a-z]+\.[a-z]+)$/;
const FORMATO_HASH_BCRYPT = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

// Hash fixo (custo 10) usado quando o utilizador não existe, para que o tempo
// de resposta não distinga utilizador inexistente de palavra-passe errada.
const HASH_FICTICIO = '$2b$10$..Sh2rAqLIillfbd/SSFoORPhCWL2HiBUytTnTmuCs77i5GzUNb/C';

const caminho = (relativo) => fileURLToPath(new URL(relativo, import.meta.url));
const FICHEIRO_UTILIZADORES = caminho('./dados/utilizadores.json');
const FICHEIRO_SUGESTOES = caminho('./dados/sugestoes.json');
const FICHEIRO_CONTRATO = caminho('../sugestoes.openapi.yaml');
const PASTA_PUBLICA = caminho('./public');

let configuracao;
try {
    configuracao = carregarConfiguracao(process.env);
} catch (erro) {
    console.error(`Erro de configuração: ${erro.message}`);
    process.exit(1);
}

const { emitirToken, exigirToken } = criarAutenticacao(configuracao);

const utilizadores = JSON.parse(await readFile(FICHEIRO_UTILIZADORES, 'utf-8'));
for (const registo of utilizadores) {
    if (!FORMATO_HASH_BCRYPT.test(registo.hashPalavraPasse)) {
        console.warn(
            `Aviso: o utilizador ${registo.utilizador} não tem um hash bcrypt válido ` +
            'em dados/utilizadores.json (ver gerar-hash.js).'
        );
    }
}

const assincrono = (manipulador) => (req, res, next) =>
    manipulador(req, res, next).catch(next);

function validarCredenciais(corpo) {
    const objeto = corpo !== null && typeof corpo === 'object' && !Array.isArray(corpo) ? corpo : {};
    const { utilizador, palavraPasse } = objeto;
    const detalhes = [];

    if (typeof utilizador !== 'string') {
        detalhes.push({ campo: 'utilizador', problema: 'Obrigatório e do tipo texto.' });
    } else if (!PADRAO_UTILIZADOR.test(utilizador)) {
        detalhes.push({
            campo: 'utilizador',
            problema: 'Deve ser um número de aluno (5 a 8 algarismos) ou um identificador nome.apelido, em minúsculas e sem acentos.'
        });
    }

    if (typeof palavraPasse !== 'string') {
        detalhes.push({ campo: 'palavraPasse', problema: 'Obrigatório e do tipo texto.' });
    } else {
        const tamanho = [...palavraPasse].length;
        if (tamanho < 8 || tamanho > 128) {
            detalhes.push({ campo: 'palavraPasse', problema: 'Deve ter entre 8 e 128 caracteres.' });
        }
    }

    return detalhes;
}

const app = express();
app.disable('x-powered-by');
app.set('etag', false);

const v2 = express.Router();
v2.use(express.json());

v2.get('/openapi.yaml', assincrono(async (req, res) => {
    const contrato = await readFile(FICHEIRO_CONTRATO, 'utf-8');
    res.set('Content-Type', 'application/yaml; charset=utf-8');
    res.send(contrato);
}));

v2.post('/tokens', assincrono(async (req, res) => {
    const detalhes = validarCredenciais(req.body);
    if (detalhes.length > 0) {
        return enviarErro(res, 400, 'Corpo do pedido não conforme com Credenciais.', detalhes);
    }

    const { utilizador, palavraPasse } = req.body;
    const registo = utilizadores.find((candidato) => candidato.utilizador === utilizador);
    const correta = await bcrypt.compare(palavraPasse, registo?.hashPalavraPasse ?? HASH_FICTICIO);
    if (!registo || !correta) {
        return enviarErro(res, 401, 'Credenciais inválidas.');
    }

    res.set('Cache-Control', 'no-store');
    res.status(200).json({
        token: emitirToken(registo),
        tipo: 'Bearer',
        expiraEm: configuracao.validade
    });
}));

v2.get('/sugestoes', exigirToken, assincrono(async (req, res) => {
    const todas = JSON.parse(await readFile(FICHEIRO_SUGESTOES, 'utf-8'));
    const visiveis = req.utilizador.papel === 'servicos'
        ? todas
        : todas.filter((sugestao) => sugestao.numeroAluno === req.utilizador.sub);

    res.set('Cache-Control', 'private, no-cache');
    res.status(200).json({
        pagina: 1,
        tamanhoPagina: 20,
        total: visiveis.length,
        itens: visiveis
    });
}));

v2.use((req, res) => {
    enviarErro(res, 404, 'Recurso não encontrado.');
});

app.use('/v2', v2);
app.use(express.static(PASTA_PUBLICA));

app.use((erro, req, res, next) => {
    if (res.headersSent) {
        return next(erro);
    }
    if (erro.type === 'entity.parse.failed') {
        return enviarErro(res, 400, 'Corpo do pedido com JSON mal formado.');
    }
    console.error(erro);
    enviarErro(res, 500, 'Erro interno do servidor.');
});

app.listen(PORTA, (erro) => {
    if (erro) {
        console.error(`Não foi possível escutar na porta ${PORTA}: ${erro.message}`);
        process.exit(1);
    }
    console.log(`Servidor a escutar em http://localhost:${PORTA}`);
});