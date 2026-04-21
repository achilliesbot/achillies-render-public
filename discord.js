// Discord Webhook Client for Achilles
import { safetyGuard, emergencyStop, SAFETY_RULES } from './safety.js';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

class DiscordClient {
    constructor(webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    async sendSaleNotification(product, amount, buyer) {
        const embed = {
            title: '⚔️ NEW TRIBUTE RECEIVED!',
            description: `A warrior has claimed **${product}**`,
            color: 0xff6b35, // Flame orange
            fields: [
                { name: '💰 Amount', value: `$${amount}`, inline: true },
                { name: '👤 Buyer', value: buyer || 'Anonymous', inline: true },
                { name: '🏆 Total Revenue', value: '$X (update me)', inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Achilles AI Warrior - 24/7 Autonomous' }
        };

        return this.sendEmbed(embed);
    }

    async sendMilestone(milestone, value) {
        const embed = {
            title: '🎉 MILESTONE ACHIEVED!',
            description: milestone,
            color: 0xffd700, // Gold
            fields: [
                { name: '📊 Value', value: value, inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Achilles AI Warrior' }
        };

        return this.sendEmbed(embed);
    }

    async sendTreasuryUpdate(balance, revenue) {
        const embed = {
            title: '💰 TREASURY UPDATE',
            color: 0x10b981, // Success green
            fields: [
                { name: '💵 Balance', value: `$${balance}`, inline: true },
                { name: '📈 Revenue', value: `$${revenue}`, inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Live from the battlefield' }
        };

        return this.sendEmbed(embed);
    }

    async sendProductLaunch(productName, price, url) {
        const embed = {
            title: '🆕 NEW WEAPON FORGED!',
            description: `**${productName}** is now available`,
            color: 0x6366f1, // Primary purple
            fields: [
                { name: '💎 Price', value: `$${price}`, inline: true },
                { name: '🔗 Link', value: url, inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Fresh from the forge' }
        };

        return this.sendEmbed(embed);
    }

    async sendEmbed(embed, isUrgent = false) {
        // Check emergency stop
        if (!emergencyStop.isActive()) {
            console.log('⛅ Notification blocked: Emergency stop active');
            return false;
        }

        // Check rate limiting
        if (!safetyGuard.canSendMessage(isUrgent)) {
            console.log('⛅ Notification blocked: Rate limit');
            return false;
        }

        // Deep sanitize ALL embed content
        if (embed.description) {
            embed.description = safetyGuard.sanitizeContent(safetyGuard.sanitizeInput(embed.description));
        }
        if (embed.title) {
            embed.title = safetyGuard.sanitizeContent(safetyGuard.sanitizeInput(embed.title));
        }
        if (embed.fields) {
            embed.fields = embed.fields.map(field => ({
                name: safetyGuard.sanitizeInput(field.name || '').substring(0, 256),
                value: safetyGuard.sanitizeInput(field.value || '').substring(0, 1024),
                inline: field.inline || false
            }));
        }
        // Remove any clickable URLs in empty channel
        if (safetyGuard.isReadOnlyMode && embed.url) {
            delete embed.url;
        }

        try {
            const response = await fetch(this.webhookUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: 'Achilles AI Warrior',
                    avatar_url: 'https://achillesalpha.onrender.com/avatar.png',
                    embeds: [embed],
                    allowed_mentions: { parse: [] } // No mentions at all in empty channel
                })
            });

            if (!response.ok) {
                throw new Error(`Discord webhook failed: ${response.status}`);
            }

            safetyGuard.recordMessage();
            console.log('✅ Discord notification sent');
            return true;
        } catch (error) {
            if (safetyGuard.shouldAlertError('discord_send')) {
                console.error('❌ Discord error:', error.message);
            }
            return false;
        }
    }

    async sendMessage(content, isUrgent = false) {
        // Check emergency stop
        if (!emergencyStop.isActive()) {
            console.log('⛅ Message blocked: Emergency stop active');
            return false;
        }

        // Check rate limiting
        if (!safetyGuard.canSendMessage(isUrgent)) {
            console.log('⛅ Message blocked: Rate limit');
            return false;
        }

        // Deep sanitize input (XSS protection)
        let safeContent = safetyGuard.sanitizeInput(content);
        
        // Check for spam
        if (safetyGuard.isSpam(safeContent)) {
            console.log('🛅 Message blocked: Spam detected');
            return false;
        }
        
        // Standard sanitization
        safeContent = safetyGuard.sanitizeContent(safeContent);
        safeContent = safetyGuard.addAutonomousLabel(safeContent);

        try {
            const response = await fetch(this.webhookUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: 'Achilles AI Warrior',
                    avatar_url: 'https://achillesalpha.onrender.com/avatar.png',
                    content: safeContent,
                    allowed_mentions: { parse: [] } // No mentions in empty channel
                })
            });

            if (!response.ok) {
                throw new Error(`Discord webhook failed: ${response.status}`);
            }

            safetyGuard.recordMessage();
            console.log('✅ Discord message sent');
            return true;
        } catch (error) {
            if (safetyGuard.shouldAlertError('discord_send')) {
                console.error('❌ Discord error:', error.message);
            }
            return false;
        }
    }

    async sendSafetyAnnouncement() {
        const safetyEmbed = {
            title: '🛡️ SAFETY GUARDRAILS ACTIVE',
            description: 'This channel operates with strict safety protocols:',
            color: 0x10b981, // Success green
            fields: [
                { name: '⏱️ Rate Limits', value: 'Max 5 msgs/hour (10 during high activity)', inline: true },
                { name: '🔒 Privacy', value: 'Wallet addresses masked. No secrets shared.', inline: true },
                { name: '📢 Mentions', value: 'No @everyone/@here unless major milestone', inline: true },
                { name: '✅ Approved Actions', value: 'Sales, milestones, treasury updates', inline: true },
                { name: '⚠️ Requires Approval', value: 'Twitter posts (3 left), price changes', inline: true },
                { name: '🛑 Emergency Stop', value: 'Type "STOP" to halt all notifications', inline: true }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Autonomous operations begin after this message' }
        };

        return this.sendEmbed(safetyEmbed, true);
    }
}

// Export for use
export { DiscordClient };

// Test if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
    const client = new DiscordClient(DISCORD_WEBHOOK_URL);
    
    console.log('Discord client ready');
    console.log('Testing connection...');
    
    // Send test notification
    client.sendMessage('⚔️ **Achilles AI Warrior is online!**\n\nDiscord integration active.\nReady to report sales, milestones, and treasury updates.')
        .then(() => console.log('Test message sent'))
        .catch(err => console.error('Test failed:', err));
}
