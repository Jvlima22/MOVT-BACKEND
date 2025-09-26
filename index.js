require('dotenv').config();
const express = require('express');
const postgres = require('postgres');
const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken'); // Removido
const { v4: uuidv4 } = require('uuid');

const databaseUrl = process.env.DATABASE_URL;
// const jwtSecret = process.env.JWT_SECRET || 'sua_chave_secreta_padrao'; // Removido

// Conexão direta com PostgreSQL usando a URL do banco de dados
const sql = postgres(databaseUrl, {
  ssl: 'require',
  max: 1, // Limitar conexões para evitar sobrecarga em testes simples
  prepare: false // Adicionado para resolver problemas de cache de plano de consulta
});

const app = express();
const port = 3000;

app.use(express.json());

// Middleware para verificar o token de sessão (session_id)
function verifyToken(req, res, next) {
  const sessionId = req.headers['authorization']; // Ou um header customizado como 'x-session-id'

  if (!sessionId) {
    return res.status(403).json({ message: 'Token de sessão não fornecido.' });
  }

  // Buscar o usuário pelo session_id
  sql`SELECT id_us FROM usuarios WHERE session_id = ${sessionId.split(' ')[1]}`
    .then(users => {
      if (users.length === 0) {
        return res.status(401).json({ message: 'Token de sessão inválido ou expirado.' });
      }
      req.userId = users[0].id_us; // Adiciona o ID do usuário à requisição
      next();
    })
    .catch(error => {
      console.error('Erro na verificação do token de sessão:', error);
      res.status(500).json({ error: 'Erro interno do servidor na verificação do token.', details: error.message });
    });
}

// Rota de Registro de Usuário
app.post('/register', async (req, res) => {
  const { nome, email, senha, cpf_cnpj, data_nascimento, telefone, tipo_documento } = req.body; // Campos expandidos

  // Validação básica dos campos obrigatórios
  if (!nome || !email || !senha || !cpf_cnpj || !data_nascimento || !telefone) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    let userCpf = null;
    let userCnpj = null;

    if (tipo_documento === 'CPF') {
      userCpf = cpf_cnpj; // O frontend já envia limpo, mas certifique-se aqui, se necessário
    } else if (tipo_documento === 'CNPJ') {
      userCnpj = cpf_cnpj; // O frontend já envia limpo, mas certifique-se aqui, se necessário
    }

    // Verificar se o email, CPF ou CNPJ já estão em uso
    const existingUser = await sql`
      SELECT id_us 
      FROM usuarios 
      WHERE email = ${email} OR cpf = ${userCpf} OR cnpj = ${userCnpj};
    `;

    if (existingUser.length > 0) {
      // Mensagens de erro mais específicas baseadas no que foi encontrado
      if (existingUser[0].email === email) {
        return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
      } else if (existingUser[0].cpf === userCpf && userCpf !== null) {
        return res.status(409).json({ error: 'Este CPF já está cadastrado.' });
      } else if (existingUser[0].cnpj === userCnpj && userCnpj !== null) {
        return res.status(409).json({ error: 'Este CNPJ já está cadastrado.' });
      } else {
        return res.status(409).json({ error: 'Erro de unicidade no banco de dados (e-mail, CPF ou CNPJ).' });
      }
    }

    const hashedPassword = await bcrypt.hash(senha, 10); // Hash da senha
    const newSessionId = uuidv4(); // Gera um UUID para o session_id

    // Converte a data de nascimento (DD/MM/AAAA) para o formato TIMESTAMP
    const [day, month, year] = data_nascimento.split('/');
    const formattedBirthDate = `${year}-${month}-${day} 00:00:00`; // Ex: 2000-01-01 00:00:00

    const [newUser] = await sql`
      INSERT INTO usuarios (nome, username, email, senha, cpf, cnpj, data_nascimento, telefone, createdat, updatedat, session_id)
      VALUES (${nome}, ${email}, ${email}, ${hashedPassword}, ${userCpf}, ${userCnpj}, ${formattedBirthDate}, ${telefone}, NOW(), NOW(), ${newSessionId})
      RETURNING id_us, nome, username, email, cpf, cnpj, data_nascimento, telefone, session_id;
    `;

    res.status(201).json({ message: 'Usuário registrado com sucesso!', user: newUser, sessionId: newSessionId });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    if (error.code === '23505') {
        return res.status(409).json({ error: 'Erro de unicidade no banco de dados (e.g., email, CPF ou CNPJ).' });
    }
    res.status(500).json({ error: 'Erro interno do servidor ao registrar usuário.', details: error.message });
  }
});

// Rota de Autenticação (Login)
app.post('/login', async (req, res) => {
  const { email, senha, sessionId: providedSessionId } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const [user] = await sql`
      SELECT id_us, email, senha, username, nome, session_id
      FROM usuarios
      WHERE email = ${email};
    `;

    if (!user) {
      return res.status(401).json({ error: 'Endereço de e-mail incorreto, tente novamente!' });
    }

    const isPasswordValid = await bcrypt.compare(senha, user.senha); // Compara a senha fornecida com o hash

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Senha inválida, tente novamente!' });
    }

    // Adicionar verificação do session_id, se fornecido na requisição
    if (providedSessionId && providedSessionId !== user.session_id) {
      return res.status(401).json({ error: 'Token de sessão inconsistente ou inválido.' });
    }

    // Retornar o session_id existente
    res.status(200).json({ message: 'Login bem-sucedido!', user: { id: user.id_us, nome: user.nome, username: user.username, email: user.email }, sessionId: user.session_id });
  } catch (error) {
    console.error('Erro ao autenticar usuário:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao autenticar usuário.', details: error.message });
  }
});


app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});


