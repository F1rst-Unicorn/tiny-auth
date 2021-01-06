/* u2f.ErrorCodes is undefined in Firefox v64 default to zero if it is undefined, same as in the u2f spec */
const U2F_ERROR_CODES_OK = typeof u2f.ErrorCodes === 'undefined' ?  0 : u2f.ErrorCodes['OK'];

/* Reject promise if u2f error, translates the error code to an `Error` */
const rejectU2fError = (resolve, reject, response) => {
    if (typeof response.errorCode === 'undefined' || response.errorCode === U2F_ERROR_CODES_OK) {
        resolve(response);
    } else {
        reject(parseError(response.errorCode));
    }
}

/* Promisify u2f.register usually taking callback function */
const u2fRegisterAsync = (appId, registerRequests, registeredKeys, opt_timeoutSeconds) =>
    new Promise((resolve, reject) =>  u2f.register(appId, registerRequests, registeredKeys, response => rejectU2fError(resolve, reject, response), opt_timeoutSeconds));

/* Promisify u2f.sign usually taking callback function */
const u2fSignAsync = (appId, challenge, registeredKeys, opt_timeoutSeconds) =>
    new Promise((resolve, reject) => u2f.sign(appId, challenge, registeredKeys, response => rejectU2fError(resolve, reject, response), opt_timeoutSeconds));

/* Get a registration request from the server
*  Register the key
*/
async function register() {
    const outputContainer = document.getElementById("output-container");

    try {
        const req = await fetch('u2f_register').then(response => response.json());

        const response = await u2fRegisterAsync(req.appId, req.registerRequests, req.registeredKeys, 30);

        if (response) {
            const registration = await postJSON('u2f_register', response);

            document.getElementById("output").innerHTML = JSON.stringify(registration.json());
            outputContainer.style.display = "block";
        }
    }
    catch(e) {
        outputContainer.innerHTML = e.message;
        outputContainer.style.display = "block";
    }
}

/* Get an authentication request from the server
*  Sign it with the key
*/
async function authenticate() {
    try {
        const req =  await fetch('u2f_sign').then(req => req.json());

        const response = await u2fSignAsync(req.appId, req.challenge, req.registeredKeys, 30);

        if (response) {
            const result = await postJSON('u2f_sign', response);
            window.location = result.url;
        }
    }
    catch(e) {
        alert(e.message);
        throw e;
    }
}

async function postJSON(url, data){
    const response = await fetch(url, { method: 'POST', body: JSON.stringify(data), headers: { 'Content-Type': 'application/json' } });
    if (response.ok) {
        return response;
    }
    throw new Error(response.statusText);
};

function parseError(errorCode) {
    var message = "Unknown error: " + errorCode;
    // In Firefox v64 u2f.ErrorCodes is undefined
    if (typeof u2f.ErrorCodes !== 'undefined') {
        for (name in u2f.ErrorCodes) {
            if (u2f.ErrorCodes[name] === errorCode) {
                message = name;
                break;
            }
        }
    }
    return new Error(message);
}
