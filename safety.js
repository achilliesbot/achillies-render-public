// Safety Guardrails for Discord Client
export const SAFETY_RULES = {
    // Rate limiting
    MAX_MESSAGES_PER_HOUR: 5,
    MAX_MESSAGES_HIGH_ACTIVITY: 10,
    MIN_GAP_MINUTES: 5,
    
    // Privacy
    WALLET_MASK_LENGTH: 6, // Show first 6 chars only
    
    // Allowed mentions
    ALLOWED_MENTIONS: ['users'], // No @everyone, @here, @roles
    
    // Content filters
    BLOCKED_WORDS: ['guaranteed', 'invest now', 'buy now', 'pump', 'dump', 'scam'],
    REQUIRED_DISCLAIMERS: {
        TRADING: '⚠️ Not financial advice. Trading at your own risk.',
        SIMULATION: '📊 Simulated results. Not real money.',
        AUTONOMOUS: '🤖 Autonomous AI Agent - Achilles'
    }
};

// Suspicious patterns for spam/bot detection
const SUSPICIOUS_PATTERNS = [
    /\b(captcha|verify|verification|claim|reward|free|airdrop)\b/gi,
    /[A-Z]{10,}/, // All caps words
    /(.{3,})\1{2,}/, // Repeated characters
    /https?:\/\/[^\s]+\.(exe|zip|rar|dmg|apk)/gi, // Dangerous file types
    /\b(discord\.gift|discordapp\.com\/gifts?)\b/gi, // Fake Discord gifts
    /[𝘡𝙕𝗭]/, // Unicode homoglyphs (fake letters)
    / qr code|scan me|verify here/gi,
    /\b(seed phrase|private key|recovery phrase)\b/gi,
];

const BLOCKED_DOMAINS = [
    'discord.gift', 'discord.gg.hack', 'discord-nitro',
    'steancomunity', 'steamcomnmunity', 'telegra.ph'
];

// Safety checker class
export class SafetyGuard {
    constructor() {
        this.messageHistory = [];
        this.lastMessageTime = 0;
        this.errorCount = {};
        this.spamAttempts = [];
        this.isReadOnlyMode = true; // Default to read-only until verified
    }

    enableInteractiveMode() {
        this.isReadOnlyMode = false;
        console.log('✅ Interactive mode enabled (verified members present)');
    }

    disableInteractiveMode() {
        this.isReadOnlyMode = true;
        console.log('🔒 Read-only mode (no verified members)');
    }

    canSendMessage(isUrgent = false) {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);
        
        // Clean old messages
        this.messageHistory = this.messageHistory.filter(t => t > oneHourAgo);
        
        // Check rate limit
        const maxMessages = isUrgent ? 
            SAFETY_RULES.MAX_MESSAGES_HIGH_ACTIVITY : 
            SAFETY_RULES.MAX_MESSAGES_PER_HOUR;
            
        if (this.messageHistory.length >= maxMessages) {
            console.log('⛔ Rate limit hit - message blocked');
            return false;
        }
        
        // Check gap
        const minGap = SAFETY_RULES.MIN_GAP_MINUTES * 60 * 1000;
        if (!isUrgent && (now - this.lastMessageTime) < minGap) {
            console.log('⛔ Gap too short - message blocked');
            return false;
        }
        
        return true;
    }

    recordMessage() {
        this.messageHistory.push(Date.now());
        this.lastMessageTime = Date.now();
    }

    maskWallet(address) {
        if (!address || address.length < 12) return '***';
        return address.substring(0, SAFETY_RULES.WALLET_MASK_LENGTH) + '...' + address.slice(-4);
    }

    sanitizeContent(content) {
        let sanitized = content;
        
        // Check blocked words
        SAFETY_RULES.BLOCKED_WORDS.forEach(word => {
            const regex = new RegExp(word, 'gi');
            sanitized = sanitized.replace(regex, '[REDACTED]');
        });
        
        // Mask any wallet addresses
        const walletRegex = /0x[a-fA-F0-9]{40}/g;
        sanitized = sanitized.replace(walletRegex, (match) => this.maskWallet(match));
        
        return sanitized;
    }

    shouldAlertError(errorType) {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);
        
        if (!this.errorCount[errorType]) {
            this.errorCount[errorType] = [];
        }
        
        // Clean old errors
        this.errorCount[errorType] = this.errorCount[errorType].filter(t => t > oneHourAgo);
        
        // Max 3 errors per hour per type
        if (this.errorCount[errorType].length >= 3) {
            return false;
        }
        
        this.errorCount[errorType].push(now);
        return true;
    }

    addAutonomousLabel(content) {
        if (!content.includes('🤖')) {
            return `${content}\n\n_🤖 Autonomous AI Agent - Achilles_`;
        }
        return content;
    }

    // Anti-spam detection
    isSpam(content) {
        // Check for suspicious patterns
        for (const pattern of SUSPICIOUS_PATTERNS) {
            if (pattern.test(content)) {
                console.log('🛡️ Spam pattern detected:', pattern);
                return true;
            }
        }

        // Check for blocked domains
        for (const domain of BLOCKED_DOMAINS) {
            if (content.toLowerCase().includes(domain)) {
                console.log('🛡️ Blocked domain detected:', domain);
                return true;
            }
        }

        // Check for rapid-fire (3+ messages in 1 minute)
        const now = Date.now();
        const oneMinuteAgo = now - 60000;
        this.spamAttempts = this.spamAttempts.filter(t => t > oneMinuteAgo);
        this.spamAttempts.push(now);
        
        if (this.spamAttempts.length >= 3) {
            console.log('🛡️ Rapid-fire detected (3+ msgs/min)');
            return true;
        }

        // Check for repetitive content
        if (this.lastContent === content) {
            console.log('🛡️ Duplicate message detected');
            return true;
        }
        this.lastContent = content;

        return false;
    }

    // XSS and injection protection
    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\(/g, '&#40;')
            .replace(/\)/g, '&#41;')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .replace(/eval\s*\(/gi, '')
            .replace(/script/gi, '');
    }

    // Verify webhook origin (Discord IPs)
    isValidDiscordIP(ip) {
        // Discord webhook IPs (simplified check)
        const discordRanges = [
            '104.16.0.0/12',
            '172.64.0.0/13',
            '162.158.0.0/15'
        ];
        // In production, implement proper CIDR check
        return true; // Placeholder - implement proper IP validation
    }

    // Empty channel protection
    canProcessCommand() {
        if (this.isReadOnlyMode) {
            console.log('🔒 Command blocked: Read-only mode (empty channel)');
            return false;
        }
        return true;
    }

    // URL safety check
    isSafeURL(url) {
        try {
            const parsed = new URL(url);
            
            // Check protocol
            if (parsed.protocol !== 'https:') {
                return false;
            }

            // Check for blocked domains
            for (const domain of BLOCKED_DOMAINS) {
                if (parsed.hostname.includes(domain)) {
                    return false;
                }
            }

            // Check for IP addresses (potential phishing)
            if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) {
                return false;
            }

            return true;
        } catch {
            return false;
        }
    }
}

// Emergency stop mechanism
export class EmergencyStop {
    constructor() {
        this.isStopped = false;
        this.stopTime = null;
    }

    stop() {
        this.isStopped = true;
        this.stopTime = Date.now();
        console.log('🛑 EMERGENCY STOP ACTIVATED');
        return 'Emergency stop activated. All notifications paused. Say RESUME to restart.';
    }

    resume() {
        this.isStopped = false;
        this.stopTime = null;
        console.log('✅ EMERGENCY STOP RELEASED');
        return 'Resuming operations. All systems active.';
    }

    checkStatus() {
        // Auto-resume after 24h
        if (this.isStopped && this.stopTime) {
            const dayAgo = Date.now() - (24 * 60 * 60 * 1000);
            if (this.stopTime < dayAgo) {
                this.resume();
                return 'Auto-resumed after 24h timeout.';
            }
        }
        return this.isStopped ? 'STOPPED' : 'ACTIVE';
    }

    isActive() {
        this.checkStatus();
        return !this.isStopped;
    }
}

// Export instances
export const safetyGuard = new SafetyGuard();
export const emergencyStop = new EmergencyStop();
