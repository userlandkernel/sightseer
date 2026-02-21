const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const { spawn } = require('child_process');
const pty = require('node-pty');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configuration
const CONFIG = {
    PASSWORD_HASH: crypto.createHash('sha256').update('secure123').digest('hex'), // Change this!
    SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
    PORT: process.env.PORT || 3000,
    MAX_SESSIONS: 10,
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    RATE_LIMIT: 100, // requests per 15 minutes
    ALLOWED_COMMANDS: [], // empty array means allow all
    DENIED_COMMANDS: ['rm -rf', 'shutdown', 'reboot', 'init', 'poweroff'], // dangerous commands
    LOG_ACTIONS: true
};

// Store active sessions
const activeSessions = new Map();
const userSessions = new Map();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, // set to true if using HTTPS
        maxAge: CONFIG.SESSION_TIMEOUT,
        httpOnly: true,
        sameSite: 'strict'
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: CONFIG.RATE_LIMIT,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Logger
function log(action, user, details = '') {
    if (!CONFIG.LOG_ACTIONS) return;
    
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${user} - ${action} ${details}\n`;
    
    console.log(logEntry.trim());
    
    // Append to log file
    fs.appendFile('terminal.log', logEntry, (err) => {
        if (err) console.error('Failed to write to log file:', err);
    });
}

// Authentication middleware
function authenticate(req, res, next) {
    const authToken = req.cookies.authToken || req.headers['x-auth-token'];
    
    if (!authToken) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const session = activeSessions.get(authToken);
    if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    // Check session expiry
    if (Date.now() > session.expires) {
        activeSessions.delete(authToken);
        return res.status(401).json({ error: 'Session expired' });
    }
    
    req.session = session;
    next();
}

// Generate auth token
function generateAuthToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Check if command is allowed
function isCommandAllowed(command) {
    // Check denied commands
    for (const denied of CONFIG.DENIED_COMMANDS) {
        if (command.includes(denied)) {
            return false;
        }
    }
    
    // If ALLOWED_COMMANDS is not empty, check if command is allowed
    if (CONFIG.ALLOWED_COMMANDS.length > 0) {
        const cmdBase = command.split(' ')[0];
        return CONFIG.ALLOWED_COMMANDS.includes(cmdBase);
    }
    
    return true;
}

// Sanitize command output
function sanitizeOutput(output) {
    // Remove ANSI escape sequences
    return output.replace(/\u001b\[\d+m/g, '');
}

// Routes

// Authentication endpoint
app.post('/api/auth', (req, res) => {
    const { password } = req.body;
    
    if (!password) {
        return res.status(400).json({ error: 'Password required' });
    }
    
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    
    if (hash === CONFIG.PASSWORD_HASH) {
        const token = generateAuthToken();
        const session = {
            token,
            created: Date.now(),
            expires: Date.now() + CONFIG.SESSION_TIMEOUT,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        };
        
        activeSessions.set(token, session);
        userSessions.set(req.ip, token);
        
        // Set cookie
        res.cookie('authToken', token, {
            maxAge: CONFIG.SESSION_TIMEOUT,
            httpOnly: true,
            sameSite: 'strict'
        });
        
        log('LOGIN_SUCCESS', req.ip, `Token: ${token.substring(0,8)}...`);
        
        res.json({ 
            success: true, 
            token,
            expires: session.expires
        });
    } else {
        log('LOGIN_FAILED', req.ip, 'Invalid password');
        res.status(401).json({ error: 'Invalid password' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticate, (req, res) => {
    const token = req.cookies.authToken;
    activeSessions.delete(token);
    userSessions.delete(req.ip);
    
    res.clearCookie('authToken');
    
    log('LOGOUT', req.ip);
    
    res.json({ success: true });
});

// Check session status
app.get('/api/status', authenticate, (req, res) => {
    res.json({
        authenticated: true,
        expires: req.session.expires,
        server: os.hostname(),
        platform: os.platform(),
        release: os.release()
    });
});

// Execute command (alternative to WebSocket)
app.post('/api/execute', authenticate, (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ error: 'Command required' });
    }
    
    if (!isCommandAllowed(command)) {
        log('COMMAND_DENIED', req.ip, command);
        return res.status(403).json({ error: 'Command not allowed' });
    }
    
    log('COMMAND_EXEC', req.ip, command);
    
    // Execute command
    const exec = require('child_process').exec;
    exec(command, {
        timeout: 10000, // 10 second timeout
        maxBuffer: 1024 * 1024 // 1MB buffer
    }, (error, stdout, stderr) => {
        const result = {
            command,
            stdout: sanitizeOutput(stdout),
            stderr: sanitizeOutput(stderr),
            code: error ? error.code : 0
        };
        
        res.json(result);
    });
});

// Get system info
app.get('/api/system', authenticate, (req, res) => {
    const info = {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        uptime: os.uptime(),
        cpus: os.cpus().length,
        memory: {
            total: os.totalmem(),
            free: os.freemem(),
            used: os.totalmem() - os.freemem()
        },
        loadavg: os.loadavg(),
        user: os.userInfo().username,
        shell: process.env.SHELL || '/bin/bash'
    };
    
    res.json(info);
});

// Socket.IO for real-time terminal
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Authentication required'));
    }
    
    const session = activeSessions.get(token);
    if (!session) {
        return next(new Error('Invalid session'));
    }
    
    if (Date.now() > session.expires) {
        activeSessions.delete(token);
        return next(new Error('Session expired'));
    }
    
    socket.session = session;
    next();
});

io.on('connection', (socket) => {
    const session = socket.session;
    log('SOCKET_CONNECT', session.ip, `Socket ID: ${socket.id}`);
    
    let ptyProcess = null;
    let commandBuffer = '';
    
    // Create pseudo-terminal
    try {
        // Get user's default shell
        const shell = process.env.SHELL || (os.platform() === 'win32' ? 'powershell.exe' : '/bin/bash');
        const shellArgs = os.platform() === 'win32' ? [] : ['--login'];
        
        ptyProcess = pty.spawn(shell, shellArgs, {
            name: 'xterm-color',
            cols: 80,
            rows: 24,
            cwd: process.env.HOME || os.homedir(),
            env: process.env
        });
        
        log('PTY_CREATED', session.ip, `Shell: ${shell}`);
        
        // Send initial message
        ptyProcess.write('clear\n');
        
        // Handle PTY output
        ptyProcess.on('data', (data) => {
            socket.emit('output', data.toString());
        });
        
        // Handle PTY exit
        ptyProcess.on('exit', (code) => {
            log('PTY_EXIT', session.ip, `Exit code: ${code}`);
            socket.emit('exit', code);
        });
        
    } catch (error) {
        log('PTY_ERROR', session.ip, error.message);
        socket.emit('error', 'Failed to create terminal session');
        return;
    }
    
    // Handle client input
    socket.on('input', (data) => {
        if (!ptyProcess) return;
        
        // Check for dangerous commands
        if (data === '\r') { // Enter key
            const command = commandBuffer.trim();
            if (command && !isCommandAllowed(command)) {
                ptyProcess.write(`echo "Command '${command}' is not allowed"\n`);
                commandBuffer = '';
                return;
            }
            log('COMMAND_INPUT', session.ip, commandBuffer);
        }
        
        commandBuffer += data;
        
        // Reset buffer on newline
        if (data === '\r' || data === '\n') {
            commandBuffer = '';
        }
        
        ptyProcess.write(data);
    });
    
    // Resize terminal
    socket.on('resize', (data) => {
        if (ptyProcess) {
            ptyProcess.resize(data.cols, data.rows);
        }
    });
    
    // Clear terminal
    socket.on('clear', () => {
        if (ptyProcess) {
            ptyProcess.write('clear\n');
        }
    });
    
    // Interrupt process (Ctrl+C)
    socket.on('interrupt', () => {
        if (ptyProcess) {
            ptyProcess.write('\x03');
        }
    });
    
    // Handle disconnect
    socket.on('disconnect', () => {
        log('SOCKET_DISCONNECT', session.ip);
        
        if (ptyProcess) {
            ptyProcess.kill();
            ptyProcess = null;
        }
    });
});

// Cleanup expired sessions
setInterval(() => {
    const now = Date.now();
    
    for (const [token, session] of activeSessions.entries()) {
        if (now > session.expires) {
            activeSessions.delete(token);
            log('SESSION_EXPIRED', session.ip, `Token: ${token.substring(0,8)}...`);
        }
    }
}, 60 * 1000); // Check every minute

// Error handling
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
server.listen(CONFIG.PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('🔐 Secure Web Terminal Server');
    console.log('='.repeat(60));
    console.log(`📡 URL:        http://localhost:${CONFIG.PORT}`);
    console.log(`🔑 Password:   ${Object.keys(CONFIG.PASSWORD_HASH).length > 0 ? '✓ Set' : '⚠ Default password'}`);
    console.log(`⏱ Session:     ${CONFIG.SESSION_TIMEOUT/60000} minutes`);
    console.log(`🛡 Rate Limit:  ${CONFIG.RATE_LIMIT} requests/15min`);
    console.log(`📝 Logging:    ${CONFIG.LOG_ACTIONS ? 'Enabled' : 'Disabled'}`);
    console.log('='.repeat(60));
    console.log(`📊 Active sessions: ${activeSessions.size}`);
    console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Received SIGTERM, shutting down gracefully...');
    
    // Kill all PTY processes
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('Received SIGINT, shutting down...');
    process.exit(0);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    log('UNCAUGHT_EXCEPTION', 'SYSTEM', error.message);
});
