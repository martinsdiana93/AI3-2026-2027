import jwt from 'jsonwebtoken';

const VALIDADE_PREDEFINIDA = 900;
const TAMANHO_MINIMO_SEGREDO = 32;
const PAPEIS = ['aluno', 'servicos'];
const FORMATO_AUTORIZACAO = /^Bearer (\S+)$/i;

// Opções passadas a jwt.verify e o que cada uma impede:
//  - algorithms: ['HS256']  impede que o token escolha o algoritmo de verificação
//    (tokens com alg "none", ou assinados com outro algoritmo, são recusados).
//  - ignoreExpiration: false  impede que um token expirado seja aceite.
//  - clockTolerance: 0  impede qualquer margem de tolerância depois do exp,
//    por isso a validade de 15 minutos é exata.
const OPCOES_VERIFICACAO = {
    algorithms: ['HS256'],
    ignoreExpiration: false,
    clockTolerance: 0
};

export function enviarErro(res, codigo, mensagem, detalhes) {
    const corpo = { codigo, mensagem };
    if (detalhes !== undefined) {
        corpo.detalhes = detalhes;
    }
    res.set('Cache-Control', 'no-store');
    res.status(codigo).json(corpo);
}

export function carregarConfiguracao(ambiente) {
    const segredo = ambiente.JWT_SEGREDO;
    if (!segredo || segredo.length < TAMANHO_MINIMO_SEGREDO) {
        throw new Error(
            `JWT_SEGREDO em falta ou com menos de ${TAMANHO_MINIMO_SEGREDO} caracteres. ` +
            'Defina-o no ficheiro .env (ver .env.exemplo).'
        );
    }

    const bruto = ambiente.JWT_VALIDADE;
    const validade = bruto === undefined || bruto === '' ? VALIDADE_PREDEFINIDA : Number(bruto);
    if (!Number.isInteger(validade) || validade <= 0) {
        throw new Error('JWT_VALIDADE deve ser um número inteiro positivo de segundos.');
    }

    return { segredo, validade };
}

export function criarAutenticacao({ segredo, validade }) {
    function emitirToken({ utilizador, nome, papel }) {
        return jwt.sign({ nome, papel }, segredo, {
            algorithm: 'HS256',
            subject: utilizador,
            expiresIn: validade
        });
    }

    function recusar(res, desafio, mensagem) {
        res.set('WWW-Authenticate', desafio);
        enviarErro(res, 401, mensagem);
    }

    function exigirToken(req, res, next) {
        const correspondencia = FORMATO_AUTORIZACAO.exec(req.get('Authorization') ?? '');
        if (!correspondencia) {
            return recusar(res, 'Bearer', 'Token de autenticação em falta ou mal formado.');
        }

        let payload;
        try {
            payload = jwt.verify(correspondencia[1], segredo, OPCOES_VERIFICACAO);
        } catch {
            return recusar(res, 'Bearer error="invalid_token"', 'Token inválido ou expirado.');
        }

        const completo =
            typeof payload === 'object' &&
            typeof payload.sub === 'string' &&
            typeof payload.nome === 'string' &&
            PAPEIS.includes(payload.papel);
        if (!completo) {
            return recusar(res, 'Bearer error="invalid_token"', 'Token inválido ou expirado.');
        }

        req.utilizador = { sub: payload.sub, nome: payload.nome, papel: payload.papel };
        next();
    }

    return { emitirToken, exigirToken };
}

export function exigirPapel(papel) {
    return (req, res, next) => {
        if (req.utilizador.papel !== papel) {
            return enviarErro(res, 403, 'O papel do utilizador não admite esta operação.');
        }
        next();
    };
}