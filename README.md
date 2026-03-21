![Logo](splash.png)
# RSMNFDB
**RedstoneShell Microsoft Not-documented Functions DB. Hidden functions, normal exapmles, real structures.**
<script>
  if (window.location.hostname === 'github.com') {
      resultsDiv.innerHTML = `
          <div style="background: #ff5555; color: white; padding: 10px; border-radius: 8px;">
              ⚠️ You visible code in repo. 
              <a href="https://redstoneshell.github.io/RSMNFDB/" style="color: yellow;">Open a site</a>, for search work.
          </div>`;
  }
</script>

Specialy database for driver devs, C# coders and other system researchers. Contains many count of undocumented functions from MDSN

## Contains
**Version**: For Windows 7
**System calls**: Names, functions, examples (C#), structures
**Is a new project, but can be at high**

## But why?
<div style="text-align: center; margin-top: 40px; padding-bottom: 20px;">
    <a href="https://uk.wikipedia.org/wiki/RSMNFDB" target="_blank" style="
        display: inline-flex;
        align-items: center;
        gap: 10px;
        background: #313244;
        color: #cdd6f4;
        text-decoration: none;
        padding: 12px 24px;
        border-radius: 12px;
        font-family: 'Segoe UI', sans-serif;
        font-weight: 600;
        transition: all 0.3s ease;
        border: 1px solid #45475a;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    " onmouseover="this.style.background='#45475a'; this.style.transform='translateY(-2px)';" 
       onmouseout="this.style.background='#313244'; this.style.transform='translateY(0)';"
       onclick="gtag('event', 'click_wiki', {'event_category': 'Social'});">
        
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L1 21H23L12 2Z" stroke="#89b4fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <text x="7" y="18" fill="#89b4fa" font-size="12" font-family="serif" font-weight="bold">W</text>
        </svg>
        
        Читати на Вікіпедії
    </a>
</div>

## Can you find something?
<input type="text" id="searchInput" placeholder="Enter something..." style="width: 100%; padding: 12px; font-size: 16px; border-radius: 8px; border: 1px solid #333; background: #1e1e2e; color: #fff;">
<div id="results" style="margin-top: 20px;">
  <p>Type in search something...</p>
</div>

<script>
  const fileList = ["RtlGetVersion", "NtCreateThreadEx", "LdrLoadDll"]; 
  const searchInput = document.getElementById('searchInput');
  const resultsDiv = document.getElementById('results');

  function highlightMatch(text, query) {
    if (!query) return text;
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(regex, '<mark style="background: #ffd966; color: #1a1a2a; padding: 0 2px; border-radius: 4px;">$1</mark>');
  }

  function renderRes() {
    const query = searchInput.value.trim();
    
    if (!query) {
      resultsDiv.innerHTML = '<p style="color: #888;">Enter something for search...</p>';
      return;
    }

    const queryLower = query.toLowerCase();
    const matches = fileList.filter(funcName => funcName.toLowerCase().includes(queryLower));

    if (matches.length === 0) {
      resultsDiv.innerHTML = `
        <div style="text-align: center; padding: 40px; background: #1a1a2a; border-radius: 12px;">
          <p style="font-size: 18px; margin-bottom: 12px;">Nothing found. Try another search :(</p>
        </div>
      `;
      return;
    }

    matches.sort((a, b) => {
      const aStarts = a.toLowerCase().startsWith(queryLower);
      const bStarts = b.toLowerCase().startsWith(queryLower);
      if (aStarts && !bStarts) return -1;
      if (!aStarts && bStarts) return 1;
      return a.localeCompare(b);
    });

    resultsDiv.innerHTML = `
      <div style="margin-bottom: 16px;">
        <strong>
          Found ${matches.length} ${matches.length === 1 ? 'function' : 'functions'}
        </strong>
      </div>
      <div style="display: flex; flex-direction: column; gap: 12px;">
        ${matches.map(funcName => `
          <div style="background: #1a1a2a; border-radius: 10px; padding: 16px 20px; border-left: 4px solid #3b82f6;">
            <a href="database/${funcName}.html" style="font-size: 18px; font-weight: 600; color: #60a5fa; text-decoration: none; font-family: monospace; display: block;">
              ${highlightMatch(funcName, query)}
            </a>
          </div>`).join('')}
      </div>
    `;
  }

  searchInput.addEventListener('input', renderRes);
</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-S8VJ6NZGFX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-S8VJ6NZGFX');
</script>
