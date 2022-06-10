  function GBI(name) { return document.getElementById(name); }

  async function BitFire_api(api_method = '', data = {}) {
      url = "{{self}}&BITFIRE_API=" + api_method;
      data.BITFIRE_API = api_method;
      data.BITFIRE_NONCE = "{{api_code}}";
      data.ts = Date.now();
      const response = await fetch(url, {
      method: 'POST',
      mode: 'cors',
      cache: 'no-cache',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      redirect: 'follow',
      referrerPolicy: 'same-origin',
      body: JSON.stringify(data)
      });
      return response;
  }

        
        function url_to_path(url) {
          console.log(url);
          let s = url.indexOf("/");
          return url.substr(s);
        }

        function htmlEscape(str) {
          return str
            .replace(/&/g, '&amp;')
            .replace(/'/g, "&apos;")
            .replace(/"/g, '&quot;')
            .replace(/>/g, '&gt;')   
            .replace(/</g, '&lt;')
            .replace(/&amp;hellip;/g, '&hellip;');    
        }

        function truncate(str, n=80){
          let out = (str.length > n) ? str.substr(0, n-1) + '&hellip;' : str;
          return htmlEscape(out);
        };


        // TODO: update response to JSON
        function add_exception(ex) {
          console.log("path: ", url_to_path(ex.getAttribute("data-ex-url")));
          console.log("code: ", ex.getAttribute("data-ex-code"));
          BitFire_api("add_api_exception", {"code": ex.getAttribute("data-ex-code"), "path": url_to_path(ex.getAttribute("data-ex-url"))})
          .then(response => response.json())
          .then(data => {
            if (!data || !data.success) {
              alert("unable to add exception " + data.note); 
            } else {
              let list = document.getElementsByClassName("ex-"+ex.getAttribute("data-ex-code"));
              console.log(ex);
              console.log(list);
              for (i=0; i<list.length; i++) {
                list[i].src="{{assets}}bandage.svg";
                list[i].classList.remove("secondary");
                list[i].classList.add("warning");
              }
              alert(data.note);
            }
          });
        }
        
        function cc_to_flag(cc) {
          if (!cc || cc.length != 2) { return ""; }
          const OFFSET = 127397;
          const codePoints = [...cc.toUpperCase()].map(c => c.codePointAt() + OFFSET);
          return String.fromCodePoint(...codePoints);
        }

        function fp(info, ...parts) {
          return parts.reduce((accumulator, value) => {
            for (let x in info) {
              if (value == info[x].type) {
                return accumulator + info[x].value;
              }
            }
            return accumulator + value;
          }, "");
        }


        
        const VERSION = {{version}};
        const VERSION_STR = "{{sym_version}}";
        const LLANG = "{{llang}}";
        const min_reducer = (accumulator, currentValue) => accumulator < currentValue ? accumulator : currentValue;
        const max_reducer = (accumulator, currentValue) => accumulator >= currentValue ? accumulator : currentValue;
        const cap = (s) => { if (typeof s !== 'string') return s; return s.charAt(0).toUpperCase() + s.slice(1); }
        
        function clamp(input, min, max) { return Math.min(Math.max(input, min), max); }

        function min(numbers) { return numbers.reduce(min_reducer); }
        function max(numbers) { return numbers.reduce(max_reducer); }
        function avg(numbers) { return numbers.reduce((a, b) => (a + b)) / numbers.length; }

        function toggle_id(param, value_id) {
            let e = GBI(value_id);
            BitFire_api("toggle_config_value", {"param": param, "value": e.value})
            .then(data => { return data.json(); })
            .then(e => {
              console.log(e);
              if (e.success) {
                alert("License activation successful!"); window.location.reload();
              } else {
                alert("unable to activate license.  please go to https://bitfire.co/support-center"); 
              } });
            return false;
        }

