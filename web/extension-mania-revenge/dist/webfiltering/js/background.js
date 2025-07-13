// hardcoded filter configuration used as example
const filterConfig = {
    rules: [
        {
            hostname: "coolctfgames.localhost",
            action: "block",
            reason: "Games"
        },
        // example filter rules for testing
        {
            // this used to exist, but is temporarily down x
            // serves as an example rule
            hostname: "social.ctf.gg",
            action: "block",
            reason: "Social Media"
        },
        {
            hostname: "ctf.gg",
            action: "block",
            reason: '"Malware"' // yes this is actually what our site has been flagged as in various places lol
        }
    ]
}

class URLParser {
  constructor(url) {
    this._href = url;
    this.parseHref();
  }

  parseHref() {
    const matchResult = this._href.match(
      /^([^\/]+:)?(\/\/)?([^\/\?#]+)(\/[^\?#]*)?(\?[^#]*)?(#.*)?/
    );

    if (matchResult) {
      if (matchResult[1] && matchResult[3]) {
        this.protocol = matchResult[1];
        this.host = matchResult[3];

        // Parse hostname and port
        const hostMatch = this.host.match(/^\[.*\]/)
          ? this.host.match(/^([\[\w*:]*\])(:(\d+))?$/)
          : this.host.match(/^([^:]+)(:(\d+))?$/);

        if (hostMatch) {
          if (hostMatch[1]) {
            this.hostname = hostMatch[1].replace(/^\*\./, '');
          }
          if (hostMatch[2]) {
            this.port = hostMatch[3];
          }
        }
      }

      // Set pathname, search, and hash
      this.pathname = matchResult[4] || '/';
      this.search = matchResult[5] || '';
      this.hash = matchResult[6] || '';
    }
  }

  get href() {
    return this._href;
  }

  set href(url) {
    this._href = url;
    this.parseHref();
  }

  params() {
    const url = this;
    if (url._params) return url._params;

    url._params = {};

    // Parse search parameters
    if (url.search && url.search !== '' && url.search !== '?') {
      url._params.search = {};
      url.search
        .replace(/^\?/, '')
        .split('&')
        .forEach((param) => {
          const [key, value] = param.split('=');
          if (key) {
            if (!url._params.search[key]) {
              url._params.search[key] = [];
            }
            if (value) {
              url._params.search[key].push(value);
            }
          }
        });
    }

    // Parse hash parameters
    if (url.hash && url.hash !== '' && url.hash !== '#') {
      url._params.hash = {};
      url.hash
        .replace(/^\#/, '')
        .split('&')
        .forEach((param) => {
          const [key, value] = param.split('=');
          if (key) {
            if (!url._paramref.hash[key]) {
              url._params.hash[key] = [];
            }
            if (value) {
              url._params.hash[key].push(value);
            }
          }
        });
    }

    return url._params;
  }

  updateSearch() {
    const url = this;
    const params = url.params();
    const searchParams = [];

    // Build search string from parameters
    for (const [key, values] of Object.entries(params.search)) {
      if (values.length > 0) {
        searchParams.push(`${key}=${values.join(',')}`);
      }
    }

    url.search = `?${searchParams.join('&')}`;
  }

  setQueryParam(key, value) {
    const url = this;
    const params = url.params();
    
    // Add or update query parameter
    if (!params.search[key]) {
      params.search[key] = [];
    }
    params.search[key].push(value);
    
    // Update search string
    url.updateSearch();
  }

  toString() {
    const url = this;
    return `${url.protocol || ''}${url.host}${url.pathname}${url.search}${url.hash}`;
  }
}

/**
 *
 * @param {chrome.webRequest.OnBeforeRequestDetails} details
 * @returns {chrome.webRequest.BlockingResponse | void}
 */
function filterRequest(details){
    console.log("Filtering request:", details);
    const url = details.url;
    // validate url format. skip internal
    const parsed = (new URLParser(url));
    const match = parsed.host.match(
        /^([a-zA-Z]+:\/\/)*([a-zA-Z0-9\_\~\-\.\:]*(\/.*)*)$/
    );
    if(!!match){
        const hostWithoutPort = parsed.hostname;
        const rule = filterConfig.rules.find(r => r.hostname === hostWithoutPort);
        if(!rule) return;
        if(rule.action === "block"){
            // redirect to custom page
            console.log("Blocking request:", hostWithoutPort);
            return {
                redirectUrl: `${chrome.runtime.getURL("block_page.html")}?hostname=${encodeURIComponent(hostWithoutPort)}&reason=${encodeURIComponent(rule.reason)}`
            };
        }
    }else{
        throw new Error("invalid host");
    }
}

chrome.webRequest.onBeforeRequest.addListener(
  filterRequest,
  {urls: ["<all_urls>"]},
  ["blocking"]
);

chrome.runtime.onStartup.addListener( () => {
    console.log("[WebFiltering] Ready");
});