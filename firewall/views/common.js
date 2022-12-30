// generic API call function
async function BitFire_api(url = '', api_method = '', data = {}) {
    // Default options are marked with *
    data.BITFIRE_API = api_method;
    data.BITFIRE_NONCE = window.BITFIRE_NONCE;
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

// document.getElementById()
function GBI(name) { return document.getElementById(name); }

// generate a random string of length (length), updated input with name config_name+_text
function rand_string(config_name, length = 32) {
    let result           = '';
    let characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for ( var i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    let e = GBI(config_name+"_text");
    if (e) { e.value = result; }
    update_str(config_name);
}

// add a new <input> to a list
// TODO: replace with document.fragment
function show_list(config_name) {
    let html = "";
    for (let i=0; i < domain_list.length; i++) {
    let id = config_name + "-" + i;
    html += '<div style="margin-bottom:5px;" id="item_'+id+'">';
    html += '<input type="text" autocomplete="off" disabled id="list_'+id+'" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="'+domain_list[i]+'">';
    html += '<div class="btn btn-danger" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="remove list element" onclick="remove_list(\''+config_name+'\', \''+domain_list[i]+'\', '+i+')"><span class="fe fe-trash"></span></div>'; 
    }
    return html;
}

// remove a list element from the server config.  reload the current page
function remove_list(config_name, value, idx) {
    console.log("config name delete", config_name, value, idx);
    BitFire_api("remove_list_elm", {"config_name":config_name, "config_value":value, "index":idx})
    .then(r => r.json())
    .then(function(res) {
    if (res.success) {
        window.location.reload();
    } else {
        alert(res.note);
        window.location.reload();
    }
    });
}

// add a list item to the server config and reload the page
function add_list(config_name) {
    let elm = GBI("new_"+config_name);
    BitFire_api("add_list_elm", {"config_name":config_name, "config_value":elm.value})
    .then(r => r.json())
    .then(function(res) {
    if (res.success) {
        window.location.reload();
    } else {
        alert(res.note);
        window.location.reload();
    }
    });
}
