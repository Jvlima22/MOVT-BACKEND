require('dotenv').config();
const express = require('express');
const postgres = require('postgres');
const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken'); // Removido
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer'); // Adicionado nodemailer

const databaseUrl = process.env.DATABASE_URL;
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;
// const jwtSecret = process.env.JWT_SECRET || 'sua_chave_secreta_padrao'; // Removido

// Conexão direta com PostgreSQL usando a URL do banco de dados
const sql = postgres(databaseUrl, {
  ssl: 'require',
  max: 1, // Limitar conexões para evitar sobrecarga em testes simples
  prepare: false // Adicionado para resolver problemas de cache de plano de consulta
});

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // Você pode mudar para outro serviço ou configurar host/port
  auth: {
    user: emailUser,
    pass: emailPass,
  },
});

// Função para gerar um código de verificação aleatório
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // Código de 6 dígitos
}

// Função para enviar o e-mail de verificação
async function sendVerificationEmail(toEmail, verificationCode) {
  const mailOptions = {
    from: emailUser,
    to: toEmail,
    subject: 'Verificação de E-mail para MOVT App',
    html: `
      <p>Olá,</p>
      <p>Obrigado por se registrar no MOVT App!</p>
      <p>Seu código de verificação é:</p>
      <h3>${verificationCode}</h3>
      <p>Este código expira em 15 minutos.</p>
      <p>Se você não solicitou esta verificação, por favor, ignore este e-mail.</p>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`E-mail de verificação enviado para ${toEmail}`);
    return true;
  } catch (error) {
    console.error(`Erro ao enviar e-mail de verificação para ${toEmail}:`, error);
    return false;
  }
}

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
  console.log('Dados recebidos do frontend (req.body):', req.body);
  const { nome, email, senha, cpf_cnpj, data_nascimento, telefone, tipo_documento } = req.body; // Campos expandidos

  // Validação básica dos campos obrigatórios
  if (!nome || !email || !senha || !cpf_cnpj || !data_nascimento || !telefone) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    let userCpf = null;
    let userCnpj = null;

    if (tipo_documento === 'CPF') {
      userCpf = cpf_cnpj;
    } else if (tipo_documento === 'CNPJ') {
      userCnpj = cpf_cnpj;
    }

    const conditions = [];
    conditions.push(sql`email = ${email}`);

    if (userCpf !== null) {
      conditions.push(sql`cpf = ${userCpf}`);
    }
    if (userCnpj !== null) {
      conditions.push(sql`cnpj = ${userCnpj}`);
    }

    let whereClause = sql`TRUE`; // Padrão para evitar WHERE vazio
    if (conditions.length > 0) {
      whereClause = sql`WHERE ${conditions[0]}`;
      for (let i = 1; i < conditions.length; i++) {
        whereClause = sql`${whereClause} OR ${conditions[i]}`;
      }
    }

    // Verificar se o email, CPF ou CNPJ já estão em uso
    const existingUser = await sql`
      SELECT id_us, email, cpf, cnpj
      FROM usuarios
      ${whereClause}
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
        return res.status(409).json({ error: 'Erro de unicidade no banco de dados.' });
      }
    }

    const hashedPassword = await bcrypt.hash(senha, 10); // Hash da senha
    const newSessionId = uuidv4(); // Gera um UUID para o session_id
    const verificationCode = generateVerificationCode(); // Gera o código de verificação
    const verificationCodeExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // Expira em 15 minutos

    // Converte a data de nascimento (DD/MM/AAAA) para o formato TIMESTAMP
    const [day, month, year] = data_nascimento.split('/');
    const formattedBirthDate = `${year}-${month}-${day} 00:00:00`; // Ex: 2000-01-01 00:00:00

    const [newUser] = await sql`
      INSERT INTO usuarios (nome, username, email, senha, cpf, cnpj, data_nascimento, telefone, createdat, updatedat, session_id, verification_code, email_verified, verification_code_expires_at)
      VALUES (${nome}, ${email}, ${email}, ${hashedPassword}, ${userCpf}, ${userCnpj}, ${formattedBirthDate}, ${telefone}, NOW(), NOW(), ${newSessionId}, ${verificationCode}, FALSE, ${verificationCodeExpiresAt})
      RETURNING id_us, nome, username, email, cpf, cnpj, data_nascimento, telefone, session_id;
    `;

    // Enviar e-mail de verificação após o registro
    const emailSent = await sendVerificationEmail(newUser.email, verificationCode);
    if (!emailSent) {
      // Opcional: registrar em log que o e-mail falhou, mas ainda retornar sucesso para o registro
      console.warn('Falha ao enviar e-mail de verificação para o novo usuário.');
    }

    res.status(201).json({ message: 'Usuário registrado com sucesso! Verifique seu e-mail.', user: newUser, sessionId: newSessionId });
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

// Nova Rota para Reenviar Código de Verificação
app.post('/user/send-verification', verifyToken, async (req, res) => {
  const userId = req.userId; // ID do usuário do middleware verifyToken

  try {
    const [user] = await sql`SELECT email, email_verified FROM usuarios WHERE id_us = ${userId}`;

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }
    if (user.email_verified) {
      return res.status(400).json({ message: 'Seu e-mail já está verificado.' });
    }

    const newVerificationCode = generateVerificationCode();
    const newVerificationCodeExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // Expira em 15 minutos

    await sql`
      UPDATE usuarios
      SET verification_code = ${newVerificationCode},
          verification_code_expires_at = ${newVerificationCodeExpiresAt},
          updatedat = NOW()
      WHERE id_us = ${userId};
    `;

    const emailSent = await sendVerificationEmail(user.email, newVerificationCode);

    if (emailSent) {
      res.status(200).json({ message: 'Novo código de verificação enviado para seu e-mail.' });
    } else {
      res.status(500).json({ error: 'Falha ao enviar o e-mail de verificação.' });
    }
  } catch (error) {
    console.error('Erro ao reenviar código de verificação:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao reenviar código.', details: error.message });
  }
});

// Nova Rota para Verificar o E-mail
app.post('/user/verify', verifyToken, async (req, res) => {
  const userId = req.userId; // ID do usuário do middleware verifyToken
  const { code } = req.body; // Código enviado pelo frontend

  if (!code) {
    return res.status(400).json({ error: 'Código de verificação é obrigatório.' });
  }

  try {
    const [user] = await sql`
      SELECT email_verified, verification_code, verification_code_expires_at
      FROM usuarios
      WHERE id_us = ${userId};
    `;

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }
    if (user.email_verified) {
      return res.status(400).json({ message: 'Seu e-mail já está verificado.' });
    }
    if (!user.verification_code || user.verification_code !== code) {
      return res.status(400).json({ error: 'Código de verificação inválido.' });
    }
    if (user.verification_code_expires_at && new Date() > user.verification_code_expires_at) {
      return res.status(400).json({ error: 'Código de verificação expirado. Solicite um novo.' });
    }

    // Se tudo estiver correto, verificar o e-mail
    await sql`
      UPDATE usuarios
      SET email_verified = TRUE,
          verification_code = NULL, -- Limpa o código após o uso
          verification_code_expires_at = NULL, -- Limpa a expiração
          updatedat = NOW()
      WHERE id_us = ${userId};
    `;

    res.status(200).json({ message: 'E-mail verificado com sucesso!' });
  } catch (error) {
    console.error('Erro ao verificar e-mail:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao verificar e-mail.', details: error.message });
  }
});


app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});


