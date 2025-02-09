const loginButton = document.getElementById("loginButton");
const login = document.getElementById("loginField");
const password = document.getElementById("passwordField");
const statusField = document.getElementById("statusField");
loginButton.onclick = async () => {
    if(!login?.value && statusField) return statusField.innerHTML = "The \"login\" field is not filled in";
    if(!password?.value && statusField) return statusField.innerHTML = "The \"password\" field is not filled in";

    const params = new Proxy(new URLSearchParams(window.location.search), {
        get: (searchParams, prop) => searchParams.get(prop),
    });
    const res = await fetch(window.location.href.split('?')[0]+"/setJWT", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            password:password.value,
            login:login.value
        })
    });
    const {message} = await res.json();
    if(statusField) statusField.innerHTML = message;
    if(res.status === 200) window.location.href = params.old;
};