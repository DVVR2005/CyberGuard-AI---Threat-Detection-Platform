// ============================================================
// CyberGuard AI - Security Advisor AI Assistant Module
// ============================================================

Router.register('ai', renderAI);

let chatMessages = [
    {
        sender: 'ai',
        text: 'Hello, I am **CyberGuard AI**, your enterprise security advisor. I have analyzed your tenant environment posture.\n\nAsk me about mitigating active critical vulnerabilities, CVE advisories, or security best practices!'
    }
];

function renderAI() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <div>
                <h1>AI Security Advisor</h1>
                <p class="text-muted">Context-aware conversational advisor trained on secure OWASP design rules.</p>
            </div>
        </div>

        <div class="row">
            <div class="col-md-9">
                <div class="card d-flex flex-column" style="height: 600px;">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">CyberGuard Advisor Chat</h5>
                        <button class="btn btn-sm btn-outline-secondary" onclick="clearAIChat()">Clear Chat</button>
                    </div>
                    
                    <!-- Chat box scroll area -->
                    <div class="card-body flex-grow-1 overflow-auto" id="ai-chat-messages-container" style="background: rgba(0,0,0,0.15);">
                        <!-- Messages injected here -->
                    </div>

                    <div class="card-footer">
                        <form id="ai-chat-form" onsubmit="submitAIChat(event)">
                            <div class="input-group">
                                <input type="text" id="ai-chat-input" class="form-control" placeholder="Ask a security question... (e.g. 'how do I fix my exposed .env file?')" required>
                                <button type="submit" class="btn btn-primary" id="ai-chat-submit-btn">
                                    <span class="btn-text">Ask AI</span>
                                    <span class="spinner-border spinner-border-sm btn-loader" style="display:none"></span>
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-3">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Suggested Prompts</h5>
                    </div>
                    <div class="card-body d-flex flex-column gap-2">
                        <button class="btn btn-outline-secondary text-start btn-sm py-2" onclick="applySuggestedPrompt('What vulnerabilities are present in my environment?')">
                            🔍 List my vulnerabilities
                        </button>
                        <button class="btn btn-outline-secondary text-start btn-sm py-2" onclick="applySuggestedPrompt('How do I secure my exposed database ports?')">
                            🗄️ How to secure DB ports
                        </button>
                        <button class="btn btn-outline-secondary text-start btn-sm py-2" onclick="applySuggestedPrompt('Tell me about the XZ Utils backdoor CVE-2024-3094')">
                            🛡️ Tell me about CVE-2024-3094
                        </button>
                        <button class="btn btn-outline-secondary text-start btn-sm py-2" onclick="applySuggestedPrompt('Show my recent SIEM alerts')">
                            🚨 Review recent SIEM alerts
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    displayAIChatMessages();
}

function displayAIChatMessages() {
    const container = document.getElementById('ai-chat-messages-container');
    if (!container) return;

    container.innerHTML = chatMessages.map(msg => {
        const isAI = msg.sender === 'ai';
        const formattedText = parseMarkdown(msg.text);
        return `
            <div class="d-flex mb-3 ${isAI ? 'justify-content-start' : 'justify-content-end'}">
                <div class="p-3 rounded-3" style="max-width: 80%; background-color: ${isAI ? 'var(--card-bg)' : '#1e3a8a'}; border: 1px solid ${isAI ? 'rgba(255,255,255,0.08)' : 'transparent'};">
                    <div class="d-flex align-items-center mb-1 text-muted" style="font-size:0.75rem; font-weight:600;">
                        <span>${isAI ? '🛡️ CYBERGUARD ADVISOR' : '👤 YOU'}</span>
                    </div>
                    <div class="text-light text-break" style="font-size:0.95rem; line-height: 1.5;">
                        ${formattedText}
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
}

async function submitAIChat(e) {
    if (e) e.preventDefault();
    const input = document.getElementById('ai-chat-input');
    const submitBtn = document.getElementById('ai-chat-submit-btn');
    if (!input || !submitBtn) return;

    const message = input.value.trim();
    if (!message) return;

    // Add user message to history
    chatMessages.push({ sender: 'user', text: message });
    displayAIChatMessages();
    input.value = '';

    // Disable input/button, show loader
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').style.display = 'none';
    submitBtn.querySelector('.btn-loader').style.display = 'inline-block';

    try {
        const data = await api('/api/ai/chat', {
            method: 'POST',
            body: {
                message: message,
                history: chatMessages.slice(-5) // Send last few messages for basic memory context
            }
        });

        // Add AI response to history
        chatMessages.push({ sender: 'ai', text: data.response });
        displayAIChatMessages();
    } catch (err) {
        chatMessages.push({ sender: 'ai', text: `Failed to connect to AI engine: **${err.message}**` });
        displayAIChatMessages();
    } finally {
        submitBtn.disabled = false;
        submitBtn.querySelector('.btn-text').style.display = 'inline';
        submitBtn.querySelector('.btn-loader').style.display = 'none';
    }
}

function applySuggestedPrompt(text) {
    const input = document.getElementById('ai-chat-input');
    if (input) {
        input.value = text;
        submitAIChat();
    }
}

function clearAIChat() {
    chatMessages = [
        {
            sender: 'ai',
            text: 'History cleared. Ask me a new security question!'
        }
    ];
    displayAIChatMessages();
}

// Simple markdown parsing function to render headers, bold, bullet points, and boxes
function parseMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    
    // Bold
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Inline code blocks
    html = html.replace(/`(.*?)`/g, '<code class="bg-dark text-cyan px-1 rounded">$1</code>');
    
    // Bullet points
    html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*?<\/li>)/gs, '<ul class="ps-3 mb-2">$1</ul>');
    
    // Headers
    html = html.replace(/^### (.*?)$/gm, '<h5 class="text-cyan mt-3 mb-2">$1</h5>');
    html = html.replace(/^## (.*?)$/gm, '<h4 class="text-cyan mt-3 mb-2">$1</h4>');
    html = html.replace(/^# (.*?)$/gm, '<h3 class="text-cyan mt-3 mb-2">$1</h3>');
    
    // Line breaks
    html = html.replace(/\n/g, '<br>');
    
    return html;
}
