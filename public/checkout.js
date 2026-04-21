// Stripe + Web3 Hybrid Payment System for PropInfera
// Automated checkout, instant delivery

const PAYMENT_CONFIG = {
    // Stripe for credit cards (LIVE KEYS)
    stripe: {
        publishableKey: 'pk_live_51SXnJMFsOD0Sk7GVRh1hzV2yYBbRHafXPZGxwHZomdgrEGGR3OvYQ1pBXk9iDHjYiGLrxI7FNwpVNfUWrz5dIvgN00pt8SIeYo',
        priceId: 'price_25USD_propinfera_report',
        successUrl: 'https://achilles-cn9c.onrender.com/success',
        cancelUrl: 'https://achilles-cn9c.onrender.com/cancel'
    },
    // Web3 for USDC
    web3: {
        chainId: 8453, // Base
        usdcContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        recipientAddress: '0x069c6012E053DFBf50390B19FaE275aD96D22ed7',
        amount: 25.00 // USDC
    },
    // Product
    product: {
        name: 'PropInfera RWA Report',
        description: 'AI-analyzed 50+ properties with RWA underwriting data',
        price: '$25'
    }
};

class PropInferaCheckout {
    constructor() {
        this.stripe = null;
        this.web3Modal = null;
        this.userEmail = '';
    }

    // Initialize checkout modal
    async initCheckout(productId = 'propinfera-premium') {
        // Show payment options modal
        const modalHTML = `
            <div id="checkout-modal" class="modal active">
                <div class="modal-content">
                    <h3>⚔️ Complete Your Purchase</h3>
                    <p class="product-name">${PAYMENT_CONFIG.product.name}</p>
                    <p class="product-price">${PAYMENT_CONFIG.product.price}</p>
                    
                    <div class="payment-options">
                        <button class="pay-btn stripe" onclick="checkout.payWithCard()">
                            <span class="icon">💳</span>
                            <span class="text">Pay with Card</span>
                            <span class="subtext">Visa, Mastercard, Amex</span>
                        </button>
                        
                        <div class="divider">or</div>
                        
                        <button class="pay-btn web3" onclick="checkout.payWithCrypto()">
                            <span class="icon">🔗</span>
                            <span class="text">Pay with USDC</span>
                            <span class="subtext">Base Network</span>
                        </button>
                    </div>
                    
                    <div class="email-input">
                        <label>Email for delivery:</label>
                        <input type="email" id="customer-email" placeholder="you@example.com" required>
                    </div>
                    
                    <button class="close-btn" onclick="checkout.closeModal()">Cancel</button>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }

    // Stripe Credit Card Payment
    async payWithCard() {
        const email = document.getElementById('customer-email').value;
        if (!email || !this.validateEmail(email)) {
            alert('Please enter a valid email address');
            return;
        }
        
        this.userEmail = email;
        
        try {
            // Load Stripe.js
            if (!window.Stripe) {
                await this.loadScript('https://js.stripe.com/v3/');
            }
            
            const stripe = window.Stripe(PAYMENT_CONFIG.stripe.publishableKey);
            
            // Create checkout session
            const response = await fetch('/api/create-checkout-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: email,
                    product: 'propinfera-premium',
                    success_url: PAYMENT_CONFIG.stripe.successUrl + '?session_id={CHECKOUT_SESSION_ID}',
                    cancel_url: PAYMENT_CONFIG.stripe.cancelUrl
                })
            });
            
            const session = await response.json();
            
            // Redirect to Stripe checkout
            const result = await stripe.redirectToCheckout({
                sessionId: session.id
            });
            
            if (result.error) {
                alert(result.error.message);
            }
            
        } catch (error) {
            console.error('Stripe checkout failed:', error);
            alert('Payment failed. Please try again or use USDC.');
        }
    }

    // Web3 USDC Payment
    async payWithCrypto() {
        const email = document.getElementById('customer-email').value;
        if (!email || !this.validateEmail(email)) {
            alert('Please enter a valid email address');
            return;
        }
        
        this.userEmail = email;
        
        try {
            // Check if MetaMask or wallet is installed
            if (!window.ethereum) {
                alert('Please install MetaMask or a Web3 wallet to pay with USDC');
                window.open('https://metamask.io', '_blank');
                return;
            }
            
            // Request wallet connection
            const accounts = await window.ethereum.request({
                method: 'eth_requestAccounts'
            });
            
            const userAddress = accounts[0];
            
            // Switch to Base network
            await this.switchToBaseNetwork();
            
            // Create Web3 provider
            const provider = new ethers.providers.Web3Provider(window.ethereum);
            const signer = provider.getSigner();
            
            // USDC Contract on Base
            const usdcContract = new ethers.Contract(
                PAYMENT_CONFIG.web3.usdcContract,
                [
                    'function transfer(address to, uint256 amount) returns (bool)',
                    'function balanceOf(address account) view returns (uint256)',
                    'function decimals() view returns (uint8)'
                ],
                signer
            );
            
            // Check USDC balance
            const decimals = await usdcContract.decimals();
            const balance = await usdcContract.balanceOf(userAddress);
            const requiredAmount = ethers.utils.parseUnits('25', decimals);
            
            if (balance.lt(requiredAmount)) {
                alert('Insufficient USDC balance. You need 25 USDC on Base network.');
                return;
            }
            
            // Show confirmation
            const confirmed = confirm(
                `Send 25 USDC to purchase PropInfera Premium Report?\n\n` +
                `From: ${userAddress.slice(0, 6)}...${userAddress.slice(-4)}\n` +
                `To: PropInfera Treasury\n` +
                `Amount: 25 USDC\n` +
                `Network: Base`
            );
            
            if (!confirmed) return;
            
            // Send USDC
            const tx = await usdcContract.transfer(
                PAYMENT_CONFIG.web3.recipientAddress,
                requiredAmount
            );
            
            // Show pending
            this.showPendingTransaction(tx.hash);
            
            // Wait for confirmation
            const receipt = await tx.wait();
            
            // Verify payment and deliver
            await this.verifyAndDeliver(tx.hash, 'usdc', email);
            
        } catch (error) {
            console.error('Web3 payment failed:', error);
            alert('Payment failed: ' + error.message);
        }
    }

    // Switch to Base Network
    async switchToBaseNetwork() {
        const baseChainId = '0x2105'; // 8453 in hex
        
        try {
            await window.ethereum.request({
                method: 'wallet_switchEthereumChain',
                params: [{ chainId: baseChainId }]
            });
        } catch (switchError) {
            // Base not added, add it
            if (switchError.code === 4902) {
                await window.ethereum.request({
                    method: 'wallet_addEthereumChain',
                    params: [{
                        chainId: baseChainId,
                        chainName: 'Base',
                        nativeCurrency: {
                            name: 'ETH',
                            symbol: 'ETH',
                            decimals: 18
                        },
                        rpcUrls: ['https://mainnet.base.org'],
                        blockExplorerUrls: ['https://basescan.org']
                    }]
                });
            } else {
                throw switchError;
            }
        }
    }

    // Verify payment and deliver report
    async verifyAndDeliver(txHash, method, email) {
        try {
            // Call backend to verify payment
            const response = await fetch('/api/verify-payment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    tx_hash: txHash,
                    method: method,
                    email: email,
                    product: 'propinfera-premium'
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showSuccessMessage(
                    'Payment received!',
                    `Your PropInfera RWA Report has been sent to ${email}`
                );
            } else {
                throw new Error(result.error || 'Verification failed');
            }
            
        } catch (error) {
            console.error('Delivery failed:', error);
            alert('Payment received but delivery failed. Contact @achillesalphaai with tx hash: ' + txHash);
        }
    }

    // Utility functions
    validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    showPendingTransaction(txHash) {
        const modal = document.querySelector('.modal-content');
        modal.innerHTML = `
            <h3>⏳ Payment Pending</h3>
            <p>Transaction submitted to Base network...</p>
            <p class="tx-hash">Hash: ${txHash.slice(0, 20)}...</p>
            <a href="https://basescan.org/tx/${txHash}" target="_blank" class="link">
                View on Basescan
            </a>
            <div class="loader"></div>
        `;
    }

    showSuccessMessage(title, message) {
        const modal = document.querySelector('.modal-content');
        modal.innerHTML = `
            <h3>✅ ${title}</h3>
            <p>${message}</p>
            <div class="success-icon">🎉</div>
            <button onclick="checkout.closeModal()" class="done-btn">Done</button>
        `;
    }

    closeModal() {
        const modal = document.getElementById('checkout-modal');
        if (modal) modal.remove();
    }
}

// Initialize checkout
const checkout = new PropInferaCheckout();

// Update CLAIM buttons to use new checkout
function initClaimButtons() {
    document.querySelectorAll('.btn').forEach(btn => {
        if (btn.textContent.includes('CLAIM')) {
            btn.onclick = () => checkout.initCheckout('propinfera-premium');
        }
    });
}

// Initialize when DOM loads
document.addEventListener('DOMContentLoaded', initClaimButtons);
