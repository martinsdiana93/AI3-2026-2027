import bcrypt from 'bcryptjs';

const CUSTO = 10;

const palavraPasse = process.argv[2];

if (palavraPasse === undefined) {
    console.error('Utilização: node gerar-hash.js "<palavra-passe>"');
    process.exit(1);
}

const tamanho = [...palavraPasse].length;
if (tamanho < 8 || tamanho > 128) {
    console.error('A palavra-passe deve ter entre 8 e 128 caracteres.');
    process.exit(1);
}

console.log(await bcrypt.hash(palavraPasse, CUSTO));