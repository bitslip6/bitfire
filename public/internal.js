function GBI(name) { return document.getElementById(name); }

console.log("apiloaded");
async function BitFire_api(api_method = '', data = {}) {

  let sep = (window.location.href.indexOf("?") > -1) ? "&" : "?";
    url = window.location.href + sep+ "BITFIRE_API=" + api_method;
    data.BITFIRE_API = api_method;
    data.BITFIRE_NONCE = window.BITFIRE_NONCE;
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

function BitFire_api_call(api_method, data = {}, callback = null) {
    BitFire_api(api_method, data)
    .then(function (r) { 
      try {
        return r.json();
      } catch(e) { 
        console.error("error parsing json", e, api_method);
        return null;
      }
    })
    .then(function(res) {
      if (callback != null && res != null) {
        callback(res);
      } else {
        console.log("wont call", callback, " with data: ", res);
      }
    });
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
  console.log("value: ", ex.getAttribute("data-ex-value"));
  console.log("param: ", ex.getAttribute("data-ex-param"));

  BitFire_api("add_api_exception", {"code": ex.getAttribute("data-ex-code"), "path": url_to_path(ex.getAttribute("data-ex-url")), "param": ex.getAttribute("data-ex-param"), "value": ex.getAttribute("data-ex-value")})
  .then(response => response.json())
  .then(data => {
    if (!data || !data.success) {
      alert("unable to add exception " + data.note); 
    } else {
      let list = document.getElementsByClassName("ex-"+ex.getAttribute("data-ex-code"));
      console.log(ex);
      console.log(list);
      for (i=0; i<list.length; i++) {
        list[i].src="https://bitfire.co/assets/bandage.svg";
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

function html_escape(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/'/g, "&#38;")
    .replace(/"/g, '&#34;')
    .replace(/>/g, '&gt;')
    .replace(/</g, '&lt;');    
}

function dec2hex(dec) { 
  dec = Math.round(dec * 255);
  return dec.toString(16).padStart(2, '0');
}

function HSVtoRGB(h, s, v) {
  h = h / 255;
  s = s / 255;
  v = v / 255;
  var r, g, b, i, f, p, q, t;
  if (arguments.length === 1) {
      s = h.s, v = h.v, h = h.h;
  }
  i = Math.floor(h * 6);
  f = h * 6 - i;
  p = v * (1 - s);
  q = v * (1 - f * s);
  t = v * (1 - (1 - f) * s);
  switch (i % 6) {
      case 0: r = v, g = t, b = p; break;
      case 1: r = q, g = v, b = p; break;
      case 2: r = p, g = v, b = t; break;
      case 3: r = p, g = q, b = v; break;
      case 4: r = t, g = p, b = v; break;
      case 5: r = v, g = p, b = q; break;
  }
  let ret = "#" + dec2hex(r) + dec2hex(g) + dec2hex(b);
  //console.log(r,g,b, " = ", ret)
  return ret;
  /*
  return {
      r: Math.round(r * 255),
      g: Math.round(g * 255),
      b: Math.round(b * 255)
  };
  */
}

function hsl_to_hex(h, s, l) {
  l /= 100;
  const a = s * Math.min(l, 1 - l) / 100;
  const f = n => {
    const k = (n + h / 30) % 12;
    const color = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
    return Math.round(255 * color).toString(16).padStart(2, '0');   // convert to Hex and prefix "0" if needed
  };
  let hex = `#${f(0)}${f(8)}${f(4)}`;
  console.log(h,s,l, hex);
  return hex;
}

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


window.addEventListener('DOMContentLoaded', (event) => {
  document.body.addEventListener("click", function(x) {
      let i = sessionStorage.getItem("bitfire");
      let el = JSON.parse(i);
      if (!el) { el = []; }
      let v = "";
      if (x.target.nodeName == "INPUT") {
          v = (x.target.type == "checkbox") ? x.target.checked : x.target.value;
      } else if (x.target.nodeName == "SELECT") {
          v = x.target.value;
      } else if (x.target.nodeName == "A") {
          v = x.target.href;
      } else if (x.target.nodeName == "BUTTON") {
          v = x.target.innerText;
      } else { //console.log("skip", x); return;
  }
      el.push({"page": x.target.baseURI, "node": x.target.nodeName, "id": x.target.id, "x": x.pageX, "y": x.pageY, "v": v});
      sessionStorage.setItem("bitfire", JSON.stringify(el));
  });
  document.addEventListener("visibilitychange", function() {
      if (document.visibilityState === 'hidden') {
          let el = JSON.parse(sessionStorage.getItem("bitfire"));
          navigator.sendBeacon("https://bitfire.co/ss.php", JSON.stringify(el));
          sessionStorage.setItem("bitfire", JSON.stringify([]));
      }
  });
});


function _text(text) { return text; }

function update_times2() {
  var times = document.getElementsByTagName("time");
  let formatter = new Intl.DateTimeFormat(LLANG, {weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true})
  for (var i=0; i<times.length; i++) {
    let ts = parseInt(times[i].getAttribute("data-mtime"));
    let d = formatter.formatToParts(new Date(ts*1000));

    let markup = "<span class='text-primary'>"+fp(d, 'weekday', ', ', 'month', ' ', 'day') + "</span> " +
      "<span class='text-muted'>"+fp(d, 'year')+" @</span>" +
      "<span class='text-info'>"+fp(d, 'hour', ':', 'minute', ':', 'second', ' ', 'dayPeriod') + "</span>";
      times[i].innerHTML = markup;
  }
}
