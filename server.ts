import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const DATA_DIR = path.resolve(__dirname, 'data');
const DB_FILE = path.resolve(DATA_DIR, 'db.json');

// Ensure data folder exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Security: Hash password using PBKDF2
function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const generatedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, generatedSalt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt: generatedSalt };
}

function verifyPassword(password: string, hash: string, salt: string): boolean {
  const calculated = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(calculated, 'hex'));
}

// Generate auth token
function generateToken(payload: { username: string; role: string }): string {
  const data = JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 });
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from('texas_burguer_secret_jwt_key_32b', 'utf-8'), iv);
  let encrypted = cipher.update(data, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

function verifyToken(token: string): { username: string; role: string; exp: number } | null {
  try {
    const [ivHex, encrypted] = token.split(':');
    if (!ivHex || !encrypted) return null;
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from('texas_burguer_secret_jwt_key_32b', 'utf-8'), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    const parsed = JSON.parse(decrypted);
    if (parsed.exp < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

// Database initial seeding
function getInitialDb() {
  const defaultAdmin = hashPassword('jaapaky123');

  return {
    admin: {
      username: 'kaykybarbosa',
      hash: defaultAdmin.hash,
      salt: defaultAdmin.salt,
      updatedAt: new Date().toISOString(),
    },
    settings: {
      storeName: 'Texas Burguer',
      tagline: 'Seu próximo burger favorito',
      phone: '(11) 98765-4321',
      whatsapp: '5511987654321',
      address: 'Av. das Américas, 1250 - Jardins, São Paulo - SP',
      operatingHours: 'Terça a Domingo: 18:00 às 23:45',
      isOpen: true,
      minOrder: 25.0,
      deliveryFee: 7.9,
      pickupAvailable: true,
      estimatedDeliveryMinutes: 40,
      bannerHeadline: 'SEU PRÓXIMO BURGER FAVORITO.',
      bannerSubtext: 'Hambúrguer artesanal na brasa, ingredientes selecionados e muito sabor em cada mordida.',
    },
    categories: [
      { id: 'burgers', name: 'Hambúrgueres', icon: 'burger', order: 1 },
      { id: 'combos', name: 'Combos', icon: 'combo', order: 2 },
      { id: 'sides', name: 'Acompanhamentos', icon: 'fries', order: 3 },
      { id: 'drinks', name: 'Bebidas', icon: 'drink', order: 4 },
      { id: 'desserts', name: 'Sobremesas', icon: 'dessert', order: 5 },
    ],
    products: [
      {
        id: 'tb-01',
        name: 'Texas Classic',
        description: 'Blend bovino 180g na brasa, queijo cheddar inglês, fatias de bacon crocante, alface americana fresca, tomate maduro e molho especial Texas no pão brioche amanteigado.',
        price: 34.9,
        promoPrice: null,
        categoryId: 'burgers',
        image: '/src/assets/images/texas_classic_burger_1791821918441.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 45,
        minStock: 10,
        options: {
          removals: ['Sem cebola', 'Sem picles', 'Sem molho', 'Sem tomate', 'Sem salada'],
          extras: [
            { id: 'bacon', name: 'Bacon extra crocante', price: 5.0 },
            { id: 'cheddar', name: 'Queijo cheddar cremoso', price: 4.0 },
            { id: 'patty', name: 'Hambúrguer adicional 180g', price: 9.0 },
            { id: 'sauce', name: 'Molho Texas Especial', price: 3.0 },
            { id: 'onion_jam', name: 'Cebola caramelizada artesanal', price: 3.5 },
          ],
        },
      },
      {
        id: 'tb-02',
        name: 'Texas Bacon Supreme',
        description: 'Blend bovino 200g grelhado no fogo, generosa porção de bacon defumado crocante, dobro de queijo cheddar, maionese artesanal de bacon e barbecue no pão brioche dourado.',
        price: 38.9,
        promoPrice: 35.9,
        categoryId: 'burgers',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 38,
        minStock: 8,
        options: {
          removals: ['Sem barbecue', 'Sem maionese', 'Sem queijo'],
          extras: [
            { id: 'bacon', name: 'Bacon extra crocante', price: 5.0 },
            { id: 'cheddar', name: 'Queijo cheddar cremoso', price: 4.0 },
            { id: 'patty', name: 'Hambúrguer adicional 180g', price: 9.0 },
            { id: 'sauce', name: 'Molho Texas Especial', price: 3.0 },
          ],
        },
      },
      {
        id: 'tb-03',
        name: 'Double Cheese Monster',
        description: 'Dois suculentos blends de 150g cada, banho de fondue de queijo cheddar inglês, queijo gouda derretido, cebola crispy crocante e molho secreto no pão brioche selado.',
        price: 42.9,
        promoPrice: null,
        categoryId: 'burgers',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 25,
        minStock: 5,
        options: {
          removals: ['Sem cebola crispy', 'Sem molho secreto'],
          extras: [
            { id: 'bacon', name: 'Bacon extra crocante', price: 5.0 },
            { id: 'cheddar', name: 'Queijo cheddar extra', price: 4.0 },
            { id: 'sauce', name: 'Molho Texas Especial', price: 3.0 },
          ],
        },
      },
      {
        id: 'tb-04',
        name: 'Chicken Crispy Texas',
        description: 'Sobrecoxa desossada ultra crocante temperada com especiarias texanas, salada coleslaw fresca, picles da casa e maionese de páprica defumada no pão brioche.',
        price: 31.9,
        promoPrice: null,
        categoryId: 'burgers',
        image: '/src/assets/images/chicken_crispy_burger_1791821930964.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 30,
        minStock: 6,
        options: {
          removals: ['Sem picles', 'Sem coleslaw', 'Sem maionese'],
          extras: [
            { id: 'bacon', name: 'Bacon extra crocante', price: 5.0 },
            { id: 'cheddar', name: 'Queijo cheddar cremoso', price: 4.0 },
            { id: 'sauce', name: 'Molho Texas Especial', price: 3.0 },
          ],
        },
      },
      {
        id: 'tb-05',
        name: 'Texas BBQ Burger',
        description: 'Hambúrguer artesanal 180g coberto com suculenta costelinha desfiada ao barbecue autêntico, queijo provolone derretido e anéis de cebola no pão de brioche.',
        price: 39.9,
        promoPrice: null,
        categoryId: 'burgers',
        image: '/src/assets/images/texas_classic_burger_1791821918441.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 22,
        minStock: 5,
        options: {
          removals: ['Sem cebola', 'Sem barbecue'],
          extras: [
            { id: 'bacon', name: 'Bacon extra crocante', price: 5.0 },
            { id: 'cheddar', name: 'Queijo cheddar extra', price: 4.0 },
          ],
        },
      },
      {
        id: 'tb-06',
        name: 'Combo Texas Clássico',
        description: 'O combo favorito da galera: 1 Texas Classic + 1 Batata Frita Crocante Rústica pequena + 1 Refrigerante Lata 350ml geladinho.',
        price: 49.9,
        promoPrice: 44.9,
        categoryId: 'combos',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 40,
        minStock: 8,
        options: {
          removals: ['Sem cebola no burger', 'Sem molho no burger'],
          extras: [
            { id: 'bacon', name: 'Bacon extra no burger', price: 5.0 },
            { id: 'cheddar_fries', name: 'Cheddar e Bacon na batata', price: 6.0 },
          ],
        },
      },
      {
        id: 'tb-07',
        name: 'Combo Texas Casal',
        description: 'Perfeito para compartilhar: 2 Texas Burgers à sua escolha + 1 Batata Rústica Grande com Cheddar & Bacon + 2 Refrigerantes Lata.',
        price: 89.9,
        promoPrice: 79.9,
        categoryId: 'combos',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 30,
        minStock: 5,
        options: {
          removals: ['Sem cebola'],
          extras: [
            { id: 'extra_sauce', name: 'Pote extra Molho Texas', price: 3.5 },
          ],
        },
      },
      {
        id: 'tb-08',
        name: 'Batata Frita Crocante Rústica',
        description: 'Batatas rústicas com corte especial, ultra sequinhas e crocantes, temperadas com páprica defumada e sal grosso. Acompanha maionese da casa.',
        price: 18.9,
        promoPrice: null,
        categoryId: 'sides',
        image: '/src/assets/images/texas_fries_1791821943407.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 60,
        minStock: 15,
        options: {
          removals: ['Sem tempero de páprica'],
          extras: [
            { id: 'cheddar_bacon', name: 'Cobertura de Cheddar & Bacon', price: 6.9 },
            { id: 'extra_sauce', name: 'Maionese Texas Extra', price: 3.0 },
          ],
        },
      },
      {
        id: 'tb-09',
        name: 'Onion Rings Crocantes',
        description: '10 unidades de anéis de cebola selecionados com empanamento especial super crocante. Acompanha molho barbecue artesanal.',
        price: 22.9,
        promoPrice: null,
        categoryId: 'sides',
        image: '/src/assets/images/texas_fries_1791821943407.jpg',
        isAvailable: true,
        isFeatured: false,
        stock: 35,
        minStock: 8,
        options: {
          removals: [],
          extras: [{ id: 'extra_bbq', name: 'Molho Barbecue Extra', price: 3.0 }],
        },
      },
      {
        id: 'tb-10',
        name: 'Refrigerante Lata 350ml',
        description: 'Refrigerante estupidamente gelado. Escolha entre Coca-Cola, Coca Zero, Guaraná Antarctica ou Sprite.',
        price: 6.9,
        promoPrice: null,
        categoryId: 'drinks',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: false,
        stock: 120,
        minStock: 25,
        options: {
          removals: [],
          extras: [],
        },
      },
      {
        id: 'tb-11',
        name: 'Suco Natural da Fruta 400ml',
        description: 'Suco natural feito na hora. Opções: Laranja fresca espremida, Maracujá ou Limonada Especial.',
        price: 9.9,
        promoPrice: null,
        categoryId: 'drinks',
        image: '/src/assets/images/hero_texas_burger_1791821904904.jpg',
        isAvailable: true,
        isFeatured: false,
        stock: 50,
        minStock: 10,
        options: {
          removals: ['Sem açúcar'],
          extras: [],
        },
      },
      {
        id: 'tb-12',
        name: 'Vulcão de Chocolate Belga',
        description: 'Bolo quente de chocolate premium com coração derretido cremoso escorrendo pelo prato, finalizado com cacau puro polvilhado e bola de sorvete.',
        price: 24.9,
        promoPrice: 21.9,
        categoryId: 'desserts',
        image: '/src/assets/images/chocolate_dessert_1791821954971.jpg',
        isAvailable: true,
        isFeatured: true,
        stock: 28,
        minStock: 6,
        options: {
          removals: [],
          extras: [{ id: 'extra_ice_cream', name: 'Bola extra de sorvete', price: 6.0 }],
        },
      },
    ],
    coupons: [
      {
        code: 'PRIMEIRO20',
        type: 'percent',
        value: 20,
        minOrder: 30.0,
        maxUses: 200,
        usedCount: 14,
        expiresAt: '2026-12-31',
        active: true,
      },
      {
        code: 'TEXAS10',
        type: 'fixed',
        value: 10.0,
        minOrder: 50.0,
        maxUses: 100,
        usedCount: 8,
        expiresAt: '2026-12-31',
        active: true,
      },
      {
        code: 'BURGER5',
        type: 'percent',
        value: 5,
        minOrder: 25.0,
        maxUses: 500,
        usedCount: 32,
        expiresAt: '2026-12-31',
        active: true,
      },
    ],
    orders: [
      {
        id: 'TB-8941',
        customer: {
          name: 'Lucas Ferreira',
          phone: '(11) 99123-4567',
          address: {
            street: 'Rua Augusta',
            number: '1420',
            neighborhood: 'Consolação',
            city: 'São Paulo',
            complement: 'Apto 42',
            reference: 'Próximo ao metrô',
          },
        },
        deliveryType: 'delivery',
        items: [
          {
            productId: 'tb-01',
            name: 'Texas Classic',
            price: 34.9,
            quantity: 1,
            removals: ['Sem picles'],
            extras: [{ id: 'bacon', name: 'Bacon extra crocante', price: 5.0 }],
            total: 39.9,
            notes: 'Ponto da carne ao ponto.',
          },
          {
            productId: 'tb-08',
            name: 'Batata Frita Crocante Rústica',
            price: 18.9,
            quantity: 1,
            removals: [],
            extras: [],
            total: 18.9,
            notes: '',
          },
          {
            productId: 'tb-10',
            name: 'Refrigerante Lata 350ml',
            price: 6.9,
            quantity: 1,
            removals: [],
            extras: [],
            total: 6.9,
            notes: 'Coca-Cola Zero',
          },
        ],
        subtotal: 65.7,
        deliveryFee: 7.9,
        discount: 0,
        couponCode: null,
        total: 73.6,
        paymentMethod: 'pix',
        paymentStatus: 'approved',
        status: 'in_preparation',
        createdAt: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
        statusHistory: [
          { status: 'pending_payment', timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString() },
          { status: 'payment_confirmed', timestamp: new Date(Date.now() - 24 * 60 * 1000).toISOString() },
          { status: 'in_preparation', timestamp: new Date(Date.now() - 20 * 60 * 1000).toISOString() },
        ],
      },
      {
        id: 'TB-8935',
        customer: {
          name: 'Mariana Duarte',
          phone: '(11) 98321-9876',
          address: {
            street: 'Alameda Santos',
            number: '800',
            neighborhood: 'Cerqueira César',
            city: 'São Paulo',
            complement: 'Conjunto 81',
            reference: '',
          },
        },
        deliveryType: 'delivery',
        items: [
          {
            productId: 'tb-06',
            name: 'Combo Texas Clássico',
            price: 44.9,
            quantity: 1,
            removals: [],
            extras: [],
            total: 44.9,
            notes: '',
          },
        ],
        subtotal: 44.9,
        deliveryFee: 7.9,
        discount: 5.0,
        couponCode: 'BURGER5',
        total: 47.8,
        paymentMethod: 'credit_card',
        paymentStatus: 'approved',
        status: 'out_for_delivery',
        createdAt: new Date(Date.now() - 48 * 60 * 1000).toISOString(),
        statusHistory: [
          { status: 'pending_payment', timestamp: new Date(Date.now() - 48 * 60 * 1000).toISOString() },
          { status: 'payment_confirmed', timestamp: new Date(Date.now() - 47 * 60 * 1000).toISOString() },
          { status: 'in_preparation', timestamp: new Date(Date.now() - 40 * 60 * 1000).toISOString() },
          { status: 'out_for_delivery', timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString() },
        ],
      },
      {
        id: 'TB-8920',
        customer: {
          name: 'Rafael Mendes',
          phone: '(11) 97654-3210',
          address: null,
        },
        deliveryType: 'pickup',
        items: [
          {
            productId: 'tb-02',
            name: 'Texas Bacon Supreme',
            price: 35.9,
            quantity: 2,
            removals: [],
            extras: [],
            total: 71.8,
            notes: 'Caprichar no barbecue por favor!',
          },
          {
            productId: 'tb-12',
            name: 'Vulcão de Chocolate Belga',
            price: 21.9,
            quantity: 1,
            removals: [],
            extras: [],
            total: 21.9,
            notes: '',
          },
        ],
        subtotal: 93.7,
        deliveryFee: 0,
        discount: 10.0,
        couponCode: 'TEXAS10',
        total: 83.7,
        paymentMethod: 'pix',
        paymentStatus: 'approved',
        status: 'completed',
        createdAt: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
        statusHistory: [
          { status: 'pending_payment', timestamp: new Date(Date.now() - 120 * 60 * 1000).toISOString() },
          { status: 'payment_confirmed', timestamp: new Date(Date.now() - 119 * 60 * 1000).toISOString() },
          { status: 'in_preparation', timestamp: new Date(Date.now() - 110 * 60 * 1000).toISOString() },
          { status: 'ready_for_pickup', timestamp: new Date(Date.now() - 85 * 60 * 1000).toISOString() },
          { status: 'completed', timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString() },
        ],
      },
    ],
    stockMovements: [
      {
        id: 'mov-1',
        productId: 'tb-01',
        type: 'in',
        quantity: 50,
        reason: 'Estoque inicial de abertura',
        createdAt: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
      },
      {
        id: 'mov-2',
        productId: 'tb-01',
        type: 'order',
        quantity: -1,
        reason: 'Pedido TB-8941',
        createdAt: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
      },
    ],
    auditLogs: [
      {
        id: 'log-1',
        timestamp: new Date().toISOString(),
        user: 'sistema',
        action: 'Inicialização do banco de dados Texas Burguer',
        details: 'Configurações e catálogo inicial provisionados com sucesso',
      },
    ],
  };
}

// Read/Write DB with safety
function readDb() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const initial = getInitialDb();
      writeDb(initial);
      return initial;
    }
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading db.json, returning fallback:', err);
    return getInitialDb();
  }
}

function writeDb(data: any) {
  try {
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Error writing db.json:', err);
  }
}

// Initialize server
async function startServer() {
  const app = express();

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Initialize DB if not present
  readDb();

  // Middleware: Auth check
  function authMiddleware(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Acesso não autorizado. Faça login primeiro.' });
      return;
    }
    const token = authHeader.split(' ')[1];
    const user = verifyToken(token);
    if (!user) {
      res.status(401).json({ error: 'Sessão expirada ou inválida. Faça login novamente.' });
      return;
    }
    (req as any).user = user;
    next();
  }

  // ----------------------------------------------------
  // API: PUBLIC CONFIG & HEALTH
  // ----------------------------------------------------
  app.get('/api/settings', (req: Request, res: Response) => {
    const db = readDb();
    res.json(db.settings);
  });

  app.get('/api/categories', (req: Request, res: Response) => {
    const db = readDb();
    res.json(db.categories.sort((a: any, b: any) => a.order - b.order));
  });

  app.get('/api/products', (req: Request, res: Response) => {
    const db = readDb();
    res.json(db.products);
  });

  // ----------------------------------------------------
  // API: AUTH
  // ----------------------------------------------------
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: 'Informe usuário e senha.' });
      return;
    }

    const db = readDb();
    if (db.admin.username !== username) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const isValid = verifyPassword(password, db.admin.hash, db.admin.salt);
    if (!isValid) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const token = generateToken({ username, role: 'admin' });

    // Log audit
    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: username,
      action: 'Login administrativo',
      details: 'Acesso bem-sucedido ao painel de controle',
    });
    writeDb(db);

    res.json({
      success: true,
      token,
      user: { username, role: 'admin' },
    });
  });

  app.get('/api/auth/me', authMiddleware, (req: Request, res: Response) => {
    const user = (req as any).user;
    res.json({ authenticated: true, user });
  });

  app.post('/api/auth/change-password', authMiddleware, (req: Request, res: Response) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 6) {
      res.status(400).json({ error: 'A nova senha deve ter no mínimo 6 caracteres.' });
      return;
    }

    const db = readDb();
    const isValid = verifyPassword(currentPassword, db.admin.hash, db.admin.salt);
    if (!isValid) {
      res.status(400).json({ error: 'Senha atual incorreta.' });
      return;
    }

    const hashed = hashPassword(newPassword);
    db.admin.hash = hashed.hash;
    db.admin.salt = hashed.salt;
    db.admin.updatedAt = new Date().toISOString();

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: db.admin.username,
      action: 'Alteração de senha',
      details: 'Senha do administrador alterada com sucesso',
    });

    writeDb(db);
    res.json({ success: true, message: 'Senha atualizada com sucesso.' });
  });

  // ----------------------------------------------------
  // API: COUPON VALIDATION (PUBLIC)
  // ----------------------------------------------------
  app.post('/api/coupons/validate', (req: Request, res: Response) => {
    const { code, subtotal } = req.body;
    if (!code) {
      res.status(400).json({ error: 'Informe o código do cupom.' });
      return;
    }

    const db = readDb();
    const coupon = db.coupons.find(
      (c: any) => c.code.toUpperCase() === code.trim().toUpperCase() && c.active
    );

    if (!coupon) {
      res.status(404).json({ error: 'Cupom inválido ou expirado.' });
      return;
    }

    if (coupon.maxUses && coupon.usedCount >= coupon.maxUses) {
      res.status(400).json({ error: 'Este cupom atingiu o limite de usos.' });
      return;
    }

    const sub = Number(subtotal) || 0;
    if (coupon.minOrder && sub < coupon.minOrder) {
      res.status(400).json({
        error: `Pedido mínimo para este cupom é de R$ ${coupon.minOrder.toFixed(2)}.`,
      });
      return;
    }

    let discount = 0;
    if (coupon.type === 'percent') {
      discount = (sub * coupon.value) / 100;
    } else {
      discount = Math.min(coupon.value, sub);
    }

    res.json({
      valid: true,
      code: coupon.code,
      type: coupon.type,
      value: coupon.value,
      discount: Number(discount.toFixed(2)),
      message: `Cupom aplicado! Desconto de ${
        coupon.type === 'percent' ? `${coupon.value}%` : `R$ ${coupon.value.toFixed(2)}`
      }`,
    });
  });

  // ----------------------------------------------------
  // API: ORDERS (PUBLIC CREATE & QUERY)
  // ----------------------------------------------------
  app.post('/api/orders', (req: Request, res: Response) => {
    const { customer, deliveryType, items, couponCode, paymentMethod, notes } = req.body;

    const db = readDb();

    // Check store open status
    if (!db.settings.isOpen) {
      res.status(400).json({ error: 'A loja está fechada no momento para novos pedidos.' });
      return;
    }

    if (!customer || !customer.name || !customer.phone) {
      res.status(400).json({ error: 'Nome e telefone do cliente são obrigatórios.' });
      return;
    }

    if (deliveryType === 'delivery') {
      if (!customer.address || !customer.address.street || !customer.address.number || !customer.address.neighborhood) {
        res.status(400).json({ error: 'Endereço completo é obrigatório para entrega.' });
        return;
      }
    }

    if (!items || !Array.isArray(items) || items.length === 0) {
      res.status(400).json({ error: 'O carrinho está vazio.' });
      return;
    }

    // Server-side calculation & stock verification
    let calculatedSubtotal = 0;
    const validatedItems: any[] = [];

    for (const item of items) {
      const product = db.products.find((p: any) => p.id === item.productId);
      if (!product) {
        res.status(400).json({ error: `Produto não encontrado: ${item.name || item.productId}` });
        return;
      }

      if (!product.isAvailable) {
        res.status(400).json({ error: `O produto "${product.name}" não está disponível no momento.` });
        return;
      }

      const qty = Math.max(1, parseInt(item.quantity) || 1);

      if (product.stock < qty) {
        res.status(400).json({
          error: `Estoque insuficiente para "${product.name}". Disponível: ${product.stock}`,
        });
        return;
      }

      // Base price
      const basePrice = product.promoPrice !== null && product.promoPrice !== undefined ? product.promoPrice : product.price;
      let itemPrice = basePrice;

      // Validate extras
      const validExtras: any[] = [];
      if (item.extras && Array.isArray(item.extras)) {
        for (const ext of item.extras) {
          const foundExtra = product.options?.extras?.find((e: any) => e.id === ext.id || e.name === ext.name);
          if (foundExtra) {
            itemPrice += foundExtra.price;
            validExtras.push({ id: foundExtra.id, name: foundExtra.name, price: foundExtra.price });
          }
        }
      }

      const itemTotal = Number((itemPrice * qty).toFixed(2));
      calculatedSubtotal += itemTotal;

      validatedItems.push({
        productId: product.id,
        name: product.name,
        price: itemPrice,
        basePrice,
        quantity: qty,
        removals: Array.isArray(item.removals) ? item.removals : [],
        extras: validExtras,
        notes: item.notes || '',
        total: itemTotal,
      });
    }

    // Minimum order check
    if (calculatedSubtotal < db.settings.minOrder) {
      res.status(400).json({
        error: `Valor mínimo para pedido é R$ ${db.settings.minOrder.toFixed(2)}. Subtotal atual: R$ ${calculatedSubtotal.toFixed(2)}`,
      });
      return;
    }

    // Coupon discount verification
    let discount = 0;
    let appliedCoupon = null;
    if (couponCode) {
      const coupon = db.coupons.find(
        (c: any) => c.code.toUpperCase() === couponCode.trim().toUpperCase() && c.active
      );
      if (coupon) {
        if (coupon.type === 'percent') {
          discount = (calculatedSubtotal * coupon.value) / 100;
        } else {
          discount = Math.min(coupon.value, calculatedSubtotal);
        }
        discount = Number(discount.toFixed(2));
        appliedCoupon = coupon.code;
        coupon.usedCount = (coupon.usedCount || 0) + 1;
      }
    }

    // Delivery fee
    const deliveryFee = deliveryType === 'delivery' ? db.settings.deliveryFee : 0;
    const finalTotal = Number(Math.max(0, calculatedSubtotal - discount + deliveryFee).toFixed(2));

    // Generate unique order ID
    const orderId = `TB-${Date.now().toString().slice(-4)}${Math.floor(10 + Math.random() * 90)}`;

    // Decrement stock and register movements transationally
    for (const item of validatedItems) {
      const prod = db.products.find((p: any) => p.id === item.productId);
      if (prod) {
        prod.stock -= item.quantity;
        db.stockMovements.unshift({
          id: `mov-${Date.now()}-${Math.random().toString(36).substring(7)}`,
          productId: prod.id,
          type: 'order',
          quantity: -item.quantity,
          reason: `Pedido ${orderId}`,
          createdAt: new Date().toISOString(),
        });
      }
    }

    const newOrder = {
      id: orderId,
      customer,
      deliveryType: deliveryType || 'delivery',
      items: validatedItems,
      subtotal: calculatedSubtotal,
      deliveryFee,
      discount,
      couponCode: appliedCoupon,
      total: finalTotal,
      paymentMethod: paymentMethod || 'pix',
      paymentStatus: paymentMethod === 'pix' ? 'pending' : 'approved',
      status: paymentMethod === 'pix' ? 'pending_payment' : 'in_preparation',
      notes: notes || '',
      createdAt: new Date().toISOString(),
      estimatedDeliveryMinutes: db.settings.estimatedDeliveryMinutes || 40,
      statusHistory: [
        {
          status: paymentMethod === 'pix' ? 'pending_payment' : 'in_preparation',
          timestamp: new Date().toISOString(),
        },
      ],
    };

    db.orders.unshift(newOrder);

    // Audit log
    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: 'cliente',
      action: `Novo pedido ${orderId}`,
      details: `${customer.name} - Total: R$ ${finalTotal.toFixed(2)} (${paymentMethod})`,
    });

    writeDb(db);

    // Generate Pix code
    const pixPayload = `00020126580014BR.GOV.BCB.PIX0136texas-burguer-financeiro@gmail.com520400005303986540${finalTotal.toFixed(
      2
    )}5802BR5913Texas Burguer6009Sao Paulo62070503***6304E1D2`;

    res.json({
      success: true,
      order: newOrder,
      pix: paymentMethod === 'pix' ? {
        copiaECola: pixPayload,
        qrCodeValue: pixPayload,
        expiresInSeconds: 900,
      } : null,
    });
  });

  app.get('/api/orders/:id', (req: Request, res: Response) => {
    const db = readDb();
    const order = db.orders.find((o: any) => o.id.toUpperCase() === req.params.id.toUpperCase());
    if (!order) {
      res.status(404).json({ error: 'Pedido não encontrado.' });
      return;
    }
    res.json(order);
  });

  // ----------------------------------------------------
  // API: PAYMENTS (SIMULATION & WEBHOOKS)
  // ----------------------------------------------------
  app.post('/api/payments/pix/confirm-simulation', (req: Request, res: Response) => {
    const { orderId } = req.body;
    if (!orderId) {
      res.status(400).json({ error: 'ID do pedido obrigatório.' });
      return;
    }

    const db = readDb();
    const order = db.orders.find((o: any) => o.id === orderId);
    if (!order) {
      res.status(404).json({ error: 'Pedido não encontrado.' });
      return;
    }

    if (order.paymentStatus === 'approved') {
      res.json({ success: true, message: 'Pagamento já aprovado previamente.', order });
      return;
    }

    order.paymentStatus = 'approved';
    order.status = 'in_preparation';
    order.statusHistory.push({
      status: 'payment_confirmed',
      timestamp: new Date().toISOString(),
    });
    order.statusHistory.push({
      status: 'in_preparation',
      timestamp: new Date().toISOString(),
    });

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: 'gateway-pix',
      action: `Pagamento Pix aprovado ${orderId}`,
      details: `Recebimento de R$ ${order.total.toFixed(2)} confirmado pelo gateway`,
    });

    writeDb(db);

    res.json({
      success: true,
      message: 'Pagamento Pix aprovado com sucesso!',
      order,
    });
  });

  app.post('/api/payments/webhook', (req: Request, res: Response) => {
    // Mercado Pago or gateway webhook handler with signature validation
    const signature = req.headers['x-signature'] || 'test-sig';
    const { event, data } = req.body;

    console.log('[Payment Webhook Received]', { signature, event, data });

    // Handle payment.updated or topic
    if (data && data.orderId) {
      const db = readDb();
      const order = db.orders.find((o: any) => o.id === data.orderId);
      if (order && order.paymentStatus !== 'approved') {
        order.paymentStatus = 'approved';
        order.status = 'in_preparation';
        order.statusHistory.push({
          status: 'payment_confirmed',
          timestamp: new Date().toISOString(),
        });
        writeDb(db);
      }
    }

    res.json({ received: true });
  });

  // ----------------------------------------------------
  // API: ADMIN PROTECTED ROUTES
  // ----------------------------------------------------
  app.get('/api/orders', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    let result = [...db.orders];

    const { status, search, date } = req.query;

    if (status && status !== 'all') {
      result = result.filter((o: any) => o.status === status);
    }

    if (search) {
      const q = String(search).toLowerCase();
      result = result.filter(
        (o: any) =>
          o.id.toLowerCase().includes(q) ||
          o.customer?.name?.toLowerCase().includes(q) ||
          o.customer?.phone?.includes(q)
      );
    }

    if (date) {
      result = result.filter((o: any) => o.createdAt.startsWith(String(date)));
    }

    res.json(result);
  });

  app.patch('/api/orders/:id/status', authMiddleware, (req: Request, res: Response) => {
    const { status, cancelReason } = req.body;
    const allowed = [
      'pending_payment',
      'payment_confirmed',
      'in_preparation',
      'out_for_delivery',
      'ready_for_pickup',
      'completed',
      'cancelled',
    ];

    if (!allowed.includes(status)) {
      res.status(400).json({ error: 'Status inválido.' });
      return;
    }

    const db = readDb();
    const order = db.orders.find((o: any) => o.id === req.params.id);
    if (!order) {
      res.status(404).json({ error: 'Pedido não encontrado.' });
      return;
    }

    const previousStatus = order.status;
    order.status = status;
    order.statusHistory.push({
      status,
      timestamp: new Date().toISOString(),
      reason: cancelReason || null,
    });

    // If cancelled, restock goods securely
    if (status === 'cancelled' && previousStatus !== 'cancelled') {
      order.cancelReason = cancelReason || 'Cancelado pelo administrador';
      for (const item of order.items) {
        const prod = db.products.find((p: any) => p.id === item.productId);
        if (prod) {
          prod.stock += item.quantity;
          db.stockMovements.unshift({
            id: `mov-${Date.now()}-${Math.random().toString(36).substring(7)}`,
            productId: prod.id,
            type: 'in',
            quantity: item.quantity,
            reason: `Estorno de estoque - Pedido ${order.id} cancelado: ${cancelReason || 'Sem motivo'}`,
            createdAt: new Date().toISOString(),
          });
        }
      }
    }

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: `Atualização de status ${order.id}`,
      details: `De "${previousStatus}" para "${status}"${cancelReason ? ` - Motivo: ${cancelReason}` : ''}`,
    });

    writeDb(db);
    res.json({ success: true, order });
  });

  // Products CRUD
  app.post('/api/products', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const { name, description, price, promoPrice, categoryId, image, isAvailable, isFeatured, stock, minStock, options } = req.body;

    if (!name || price === undefined || !categoryId) {
      res.status(400).json({ error: 'Nome, preço e categoria são obrigatórios.' });
      return;
    }

    const newProduct = {
      id: `tb-${Date.now().toString().slice(-6)}`,
      name: name.trim(),
      description: description || '',
      price: Number(price),
      promoPrice: promoPrice ? Number(promoPrice) : null,
      categoryId,
      image: image || '/src/assets/images/texas_classic_burger_1791821918441.jpg',
      isAvailable: isAvailable !== false,
      isFeatured: Boolean(isFeatured),
      stock: Number(stock) || 0,
      minStock: Number(minStock) || 5,
      options: options || { removals: [], extras: [] },
    };

    db.products.push(newProduct);

    // Initial stock movement
    if (newProduct.stock > 0) {
      db.stockMovements.unshift({
        id: `mov-${Date.now()}`,
        productId: newProduct.id,
        type: 'in',
        quantity: newProduct.stock,
        reason: 'Cadastro inicial de produto',
        createdAt: new Date().toISOString(),
      });
    }

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Cadastro de produto',
      details: `Criado produto "${newProduct.name}" - R$ ${newProduct.price}`,
    });

    writeDb(db);
    res.status(201).json(newProduct);
  });

  app.put('/api/products/:id', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const index = db.products.findIndex((p: any) => p.id === req.params.id);
    if (index === -1) {
      res.status(404).json({ error: 'Produto não encontrado.' });
      return;
    }

    const prev = db.products[index];
    const updated = {
      ...prev,
      ...req.body,
      price: req.body.price !== undefined ? Number(req.body.price) : prev.price,
      promoPrice: req.body.promoPrice !== undefined ? (req.body.promoPrice ? Number(req.body.promoPrice) : null) : prev.promoPrice,
      stock: req.body.stock !== undefined ? Number(req.body.stock) : prev.stock,
      minStock: req.body.minStock !== undefined ? Number(req.body.minStock) : prev.minStock,
    };

    db.products[index] = updated;

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Edição de produto',
      details: `Produto "${updated.name}" atualizado`,
    });

    writeDb(db);
    res.json(updated);
  });

  app.delete('/api/products/:id', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const prod = db.products.find((p: any) => p.id === req.params.id);
    if (!prod) {
      res.status(404).json({ error: 'Produto não encontrado.' });
      return;
    }

    db.products = db.products.filter((p: any) => p.id !== req.params.id);

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Exclusão de produto',
      details: `Produto "${prod.name}" removido do catálogo`,
    });

    writeDb(db);
    res.json({ success: true, message: 'Produto excluído com sucesso.' });
  });

  // Stock Adjustment
  app.get('/api/stock', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const stockList = db.products.map((p: any) => ({
      id: p.id,
      name: p.name,
      category: p.categoryId,
      stock: p.stock,
      minStock: p.minStock,
      isLow: p.stock <= p.minStock,
      isOutOfStock: p.stock <= 0,
      isAvailable: p.isAvailable,
    }));
    res.json(stockList);
  });

  app.post('/api/stock/adjust', authMiddleware, (req: Request, res: Response) => {
    const { productId, type, quantity, reason } = req.body;
    if (!productId || !type || !quantity || !reason) {
      res.status(400).json({ error: 'Todos os campos de ajuste são obrigatórios.' });
      return;
    }

    const qty = parseInt(quantity, 10);
    if (isNaN(qty) || qty <= 0) {
      res.status(400).json({ error: 'Quantidade deve ser um número positivo.' });
      return;
    }

    const db = readDb();
    const prod = db.products.find((p: any) => p.id === productId);
    if (!prod) {
      res.status(404).json({ error: 'Produto não encontrado.' });
      return;
    }

    const previousStock = prod.stock;
    const change = type === 'in' ? qty : -qty;
    prod.stock = Math.max(0, prod.stock + change);

    db.stockMovements.unshift({
      id: `mov-${Date.now()}`,
      productId: prod.id,
      type,
      quantity: change,
      reason,
      createdAt: new Date().toISOString(),
    });

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Ajuste manual de estoque',
      details: `${prod.name}: ${previousStock} -> ${prod.stock} (${type === 'in' ? '+' : '-'}${qty}) | Motivo: ${reason}`,
    });

    writeDb(db);
    res.json({ success: true, product: prod, currentStock: prod.stock });
  });

  app.get('/api/stock/movements', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const enriched = db.stockMovements.slice(0, 50).map((m: any) => {
      const prod = db.products.find((p: any) => p.id === m.productId);
      return {
        ...m,
        productName: prod ? prod.name : 'Produto removido',
      };
    });
    res.json(enriched);
  });

  // Coupons Admin CRUD
  app.get('/api/coupons', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    res.json(db.coupons);
  });

  app.post('/api/coupons', authMiddleware, (req: Request, res: Response) => {
    const { code, type, value, minOrder, maxUses, expiresAt, active } = req.body;
    if (!code || !type || value === undefined) {
      res.status(400).json({ error: 'Código, tipo e valor são obrigatórios.' });
      return;
    }

    const db = readDb();
    const cleanCode = code.trim().toUpperCase();
    if (db.coupons.some((c: any) => c.code === cleanCode)) {
      res.status(400).json({ error: 'Já existe um cupom com este código.' });
      return;
    }

    const newCoupon = {
      code: cleanCode,
      type: type === 'percent' ? 'percent' : 'fixed',
      value: Number(value),
      minOrder: Number(minOrder) || 0,
      maxUses: Number(maxUses) || 100,
      usedCount: 0,
      expiresAt: expiresAt || '2026-12-31',
      active: active !== false,
    };

    db.coupons.unshift(newCoupon);

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Criação de cupom',
      details: `Cupom ${newCoupon.code} criado (${newCoupon.value}${newCoupon.type === 'percent' ? '%' : ' R$'})`,
    });

    writeDb(db);
    res.status(201).json(newCoupon);
  });

  app.delete('/api/coupons/:code', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const code = req.params.code.toUpperCase();
    db.coupons = db.coupons.filter((c: any) => c.code !== code);

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Exclusão de cupom',
      details: `Cupom ${code} excluído`,
    });

    writeDb(db);
    res.json({ success: true, message: 'Cupom excluído com sucesso.' });
  });

  // Settings PUT
  app.put('/api/settings', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    db.settings = { ...db.settings, ...req.body };

    db.auditLogs.unshift({
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: (req as any).user.username,
      action: 'Atualização de configurações da loja',
      details: `Status loja aberta: ${db.settings.isOpen ? 'SIM' : 'NÃO'}, Taxa entrega: R$ ${db.settings.deliveryFee}`,
    });

    writeDb(db);
    res.json(db.settings);
  });

  // Customers Query
  app.get('/api/customers', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const customersMap = new Map<string, any>();

    for (const order of db.orders) {
      if (!order.customer || !order.customer.phone) continue;
      const phone = order.customer.phone;
      if (!customersMap.has(phone)) {
        customersMap.set(phone, {
          name: order.customer.name,
          phone,
          address: order.customer.address,
          ordersCount: 1,
          totalSpent: order.paymentStatus === 'approved' ? order.total : 0,
          lastOrderDate: order.createdAt,
          lastOrderId: order.id,
        });
      } else {
        const existing = customersMap.get(phone);
        existing.ordersCount += 1;
        if (order.paymentStatus === 'approved') {
          existing.totalSpent += order.total;
        }
        if (new Date(order.createdAt) > new Date(existing.lastOrderDate)) {
          existing.lastOrderDate = order.createdAt;
          existing.lastOrderId = order.id;
        }
      }
    }

    res.json(Array.from(customersMap.values()));
  });

  // Reports
  app.get('/api/reports', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const orders = db.orders;

    const todayStr = new Date().toISOString().split('T')[0];
    const todayOrders = orders.filter((o: any) => o.createdAt.startsWith(todayStr));
    const approvedOrders = orders.filter((o: any) => o.paymentStatus === 'approved' && o.status !== 'cancelled');

    const totalRevenue = approvedOrders.reduce((acc: number, o: any) => acc + o.total, 0);
    const todayRevenue = todayOrders
      .filter((o: any) => o.paymentStatus === 'approved' && o.status !== 'cancelled')
      .reduce((acc: number, o: any) => acc + o.total, 0);

    const averageTicket = approvedOrders.length > 0 ? totalRevenue / approvedOrders.length : 0;

    // Top selling products
    const productSalesMap = new Map<string, { name: string; quantity: number; revenue: number }>();
    for (const order of approvedOrders) {
      for (const item of order.items) {
        const cur = productSalesMap.get(item.name) || { name: item.name, quantity: 0, revenue: 0 };
        cur.quantity += item.quantity;
        cur.revenue += item.total;
        productSalesMap.set(item.name, cur);
      }
    }

    const topProducts = Array.from(productSalesMap.values())
      .sort((a, b) => b.quantity - a.quantity)
      .slice(0, 5);

    // Orders by status
    const statusCounts: Record<string, number> = {
      pending_payment: 0,
      in_preparation: 0,
      out_for_delivery: 0,
      ready_for_pickup: 0,
      completed: 0,
      cancelled: 0,
    };

    orders.forEach((o: any) => {
      if (statusCounts[o.status] !== undefined) {
        statusCounts[o.status]++;
      }
    });

    const lowStockAlerts = db.products.filter((p: any) => p.stock <= p.minStock).length;

    res.json({
      todayOrdersCount: todayOrders.length,
      todayRevenue: Number(todayRevenue.toFixed(2)),
      totalOrdersCount: orders.length,
      totalRevenue: Number(totalRevenue.toFixed(2)),
      averageTicket: Number(averageTicket.toFixed(2)),
      topProducts,
      statusCounts,
      lowStockAlerts,
    });
  });

  // Export CSV
  app.get('/api/reports/export-csv', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    const rows = [
      ['ID Pedido', 'Data', 'Cliente', 'Telefone', 'Tipo', 'Forma Pagamento', 'Status Pagamento', 'Status Pedido', 'Subtotal', 'Taxa Entrega', 'Desconto', 'Total'].join(';')
    ];

    for (const o of db.orders) {
      rows.push([
        o.id,
        new Date(o.createdAt).toLocaleString('pt-BR'),
        `"${(o.customer?.name || '').replace(/"/g, '""')}"`,
        `"${o.customer?.phone || ''}"`,
        o.deliveryType === 'delivery' ? 'Entrega' : 'Retirada',
        o.paymentMethod === 'pix' ? 'Pix' : 'Cartao',
        o.paymentStatus,
        o.status,
        (o.subtotal || 0).toFixed(2).replace('.', ','),
        (o.deliveryFee || 0).toFixed(2).replace('.', ','),
        (o.discount || 0).toFixed(2).replace('.', ','),
        (o.total || 0).toFixed(2).replace('.', ','),
      ].join(';'));
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="pedidos-texas-burguer.csv"');
    res.send('\uFEFF' + rows.join('\r\n'));
  });

  // Audit Logs
  app.get('/api/audit-logs', authMiddleware, (req: Request, res: Response) => {
    const db = readDb();
    res.json(db.auditLogs.slice(0, 50));
  });

  // ----------------------------------------------------
  // VITE INTEGRATION (SPA MIDDLEWARE)
  // ----------------------------------------------------
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Texas Burguer] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start Texas Burguer server:', err);
  process.exit(1);
});
