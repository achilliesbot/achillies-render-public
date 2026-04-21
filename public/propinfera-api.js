// PropInfera Real Analyzer API Client
// Connects to BNKR LLM via /api/analyze — NO fallback/fake data

class PropInferaAPI {
    constructor() {
        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000;
    }

    async analyzeProperty(input, type = 'url') {
        const cacheKey = `${type}:${input}`;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < this.cacheTimeout) {
                return cached.data;
            }
        }

        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, input, url: type === 'url' ? input : undefined })
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({ error: 'Server error' }));
            throw new Error(err.error || `API error: ${response.status}`);
        }

        const data = await response.json();
        this.cache.set(cacheKey, { data, timestamp: Date.now() });
        return data;
    }
}

const propInferaAPI = new PropInferaAPI();

async function analyzePropertyReal() {
    const url = document.getElementById('property-url').value.trim();
    if (!url) { alert('Please enter a property URL'); return; }

    showLoading();
    try {
        const result = await propInferaAPI.analyzeProperty(url, 'url');
        displayRealResults(result);
    } catch (error) {
        hideLoading();
        alert('Analysis failed: ' + error.message);
    }
}

async function analyzeAddressReal() {
    const address = document.getElementById('property-address').value.trim();
    if (!address) { alert('Please enter a property address'); return; }

    showLoading();
    try {
        const result = await propInferaAPI.analyzeProperty(address, 'address');
        displayRealResults(result);
    } catch (error) {
        hideLoading();
        alert('Analysis failed: ' + error.message);
    }
}

function displayRealResults(data) {
    hideLoading();
    const analysis = data.analysis || {};
    const metrics = analysis.metrics || {};
    const property = data.property || {};
    const raw = data.raw || {};

    const price = metrics.list_price || property.list_price || 0;
    const score = analysis.deal_score || raw.propInferaScore || 0;
    const rent = metrics.rent_estimate || property.rent_estimate || 0;
    const cashflow = metrics.cash_flow || 0;
    const capRate = metrics.cap_rate || 0;

    document.getElementById('result-price').textContent = price ? '$' + price.toLocaleString() : 'N/A';
    document.getElementById('result-score').textContent = score ? score + '/100' : 'N/A';
    document.getElementById('result-rent').textContent = rent ? '$' + rent.toLocaleString() + '/mo' : 'N/A';
    document.getElementById('result-cashflow').textContent = cashflow ? (cashflow >= 0 ? '+' : '') + '$' + Math.round(cashflow) + '/mo' : 'N/A';

    document.getElementById('result-assessment').textContent = analysis.recommendation || raw.reasoning || 'Analysis complete.';
    document.getElementById('result-verdict').textContent =
        (analysis.verdict || raw.recommendation || 'ANALYZING') +
        (analysis.confidence_score ? ' — Confidence: ' + Math.round(analysis.confidence_score * 100) + '%' : '');

    const risks = analysis.risk_flags || [];
    if (risks.length > 0) {
        document.getElementById('result-risks').innerHTML = risks.map(r => '<li>' + r + '</li>').join('');
    } else {
        // Show raw data highlights if no parsed risk flags
        const highlights = [];
        if (raw.zipcodeIntel) {
            if (raw.zipcodeIntel.crimeLevel) highlights.push('Crime: ' + raw.zipcodeIntel.crimeLevel);
            if (raw.zipcodeIntel.medianHomePrice) highlights.push('Median price: ' + raw.zipcodeIntel.medianHomePrice);
        }
        if (raw.walkScore) highlights.push('Walk score: ' + raw.walkScore);
        if (raw.schoolRatings) {
            const s = raw.schoolRatings;
            highlights.push('Schools: Elem ' + (s.elementary||'?') + ' / Mid ' + (s.middle||'?') + ' / High ' + (s.high||'?'));
        }
        if (highlights.length > 0) {
            document.getElementById('result-risks').innerHTML = highlights.map(h => '<li>' + h + '</li>').join('');
        } else {
            document.getElementById('result-risks').innerHTML = '<li>No specific risk flags identified</li>';
        }
    }

    document.getElementById('analysis-results').style.display = 'block';
    document.getElementById('analysis-results').scrollIntoView({ behavior: 'smooth' });
}

window.propInferaAPI = propInferaAPI;
window.analyzePropertyReal = analyzePropertyReal;
window.analyzeAddressReal = analyzeAddressReal;
window.displayRealResults = displayRealResults;
