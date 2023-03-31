
function bitGBI(name) { return document.getElementById(name); }

function bitSHOW(event) {
    event.preventDefault();
    console.log("bit show!", event);

    let markup = 
"\<style>.bitfire-modal{ position:fixed;top:15%;left:35%;width:30%;min-width:30rem;height:29rem;background-color:#F0F0F5;border:1px solid #666;border-radius:.4rem;padding:2rem;line-height:2.2rem;color:#444;box-shadow:3px 3px 10px 3px rgba(0,0,0,0.2);}\
.bitfire-header{font-size:1.5rem; text-align:center;line-height:2rem;margin:0 0 1rem 0;font-size:1.5rem;}\
.bitform{font-size:1rem;}\
 </style>\
<div class='bitfire-modal'>\
<p class='bitfire-header'>Why are you deactivating BitFire?</p><hr>\
<form id='bitreason' style='color:#555;' class='bitform' method='POST' action='https://bitfire.co/zxf.php'>\
<input type='radio' name='reason' value='1' id='complex'><label for='complex'> Too complicated</label><br>\
<input type='radio' name='reason' value='2' id='nofix'><label for='nofix'> Didn't fix my site</label><br>\
<input type='radio' name='reason' value='3' id='toomuch'><label for='toomuch'> Blocked too much traffic</label><br>\
<input type='radio' name='reason' value='4' id='testmain'><label for='testmain'> Testing / Maintenance</label> <br>\
<input type='radio' name='reason' value='5' id='bitcrash'><label for='bitcrash'> Plugin Broke / Crashed</label> <br>\
<label>Plugin Incompatibility:</label><br><input type='text' name='bitplugin' value='' style='width:20rem;font-size:1.25rem'><br>\
<label>Feedback:</label><br> <textarea id='bitfeedback' name='bitfeedback' rows='3' cols='50' style=''></textarea><br>\
<button style='cursor:pointer'>deactivate</button>\
</form></div>";
let c = bitGBI("wpbody-content");
c.innerHTML += markup;

bitGBI('bitreason').addEventListener('submit', (e) => {
    // Prevent the default form submit
    e.preventDefault();

    // Store reference to form to make later code easier to read
    const form = new FormData(bitGBI("bitreason"));
    const data = Object.fromEntries(form.entries());
    data.reason = form.getAll("reason");
    const json = JSON.stringify(data);
    const beta = btoa(json);
    console.log("json", json);
    console.log("btoa", beta)

    // Post data using the Fetch API
    const r = fetch("https://bitfire.co/zxf.php", {
        method: "POST",
        credentials: "omit",
        referrerPolicy: "strict-origin-when-cross-origin",
        body: beta
    });

    window.location = event.target.href;
});

let e = bitGBI("deactivate-bitfire");
e.removeEventListener("click", bitSHOW);
return false;
}

let e = bitGBI("deactivate-bitfire");
e.addEventListener("click", bitSHOW);