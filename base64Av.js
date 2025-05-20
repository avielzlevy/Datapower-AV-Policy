const urlopen = require('urlopen');
const sm = require('service-metadata');
const util = require('util');
const converter = require('json-xml-converter');
if(!session.parameters.AllowEmpty) session.parameters.AllowEmpty = "true"

//sm.setVar('var://service/mpgw/skip-backside', true);
const avUrl = 'https://x.x.x.x/avbase64sync';

const log = (level, message) => {
    console[level](`Police-AV -> ${message}`);
};

const isBase64Encoded = input => {
    const base64CharacterSet = /^[A-Za-z0-9+/]+={0,2}$/;
    console.alert(`input is ${input}`)
	if (input.length === 0||Object.keys(input).length === 0 && session.parameters.AllowEmpty === "true")
		return true
    log('debug', `input length is ${input.length} input is ${input}`)
    if (input.length % 4 !== 0) {
        log('debug', 'input length is not a multiple of 4');
        return false;
    }
    if (!base64CharacterSet.test(input)) {
        log('debug', 'input contains invalid characters');
        return false;
    }
    const paddingIndex = input.indexOf('=');
    if (paddingIndex !== -1 && paddingIndex < input.length - 2) {
        log('debug', 'input contains padding character not correctly placed');
        return false;
    }
    if (/[^ -~]/.test(input)) {
        log('debug', 'input contains ASCII control characters');
        return false;
    }
    return true;
};

const isPDF = input => {
    if (input.length < 668) {
        log('alert', 'file is too short');
        return false;
    }
    const decoded = Buffer.from(input, 'base64');
    log('debug', `decoded string length is ${decoded.length}`)
    log('debug', 'decoded successfully')
    // if (decoded.toString('ascii', 0, 4) === '%PDF') {
    //     log('debug', 'input is a pdf');
    //     return true;
    // }
    log('debug', 'input is not a pdf');
    return true;
};

const fixBadger = obj => {
    const res = Array.isArray(obj) ? [] : {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (obj[key] && typeof obj[key] === 'object') {
                if (obj[key].hasOwnProperty('$')) {
                    res[key] = obj[key]['$'];
                } else {
                    res[key] = fixBadger(obj[key]);
                }
            } else {
                res[key] = obj[key];
            }
        }
    }
    return res;
};
const unfixBadger = obj => {
    const res = Array.isArray(obj) ? [] : {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (typeof obj[key] === 'string') {
                res[key] = { $: obj[key] };
            } else if (obj[key] && typeof obj[key] === 'object') {
                res[key] = unfixBadger(obj[key]);
            } else {
                res[key] = obj[key];
            }
        }
    }
    return res;
};

function xpathToJSONPath(xpath) {
    // Split the XPath by '/' and filter out empty strings
    const nodes = xpath.split('/').filter(n => n);

    // Transform each node to its JavaScript equivalent
    const path = nodes.map(node => {
        // Extract the local name using a regular expression
        const match = node.match(/\[local-name\(\)='([^']+)'\]/);
        if (match) {
            return match[1];
        } else {
            // If the node does not match the pattern, return it as is
            return node;
        }
    });

    // Join the transformed nodes with '.'
    return path.join('.');
}


function extractBase64FromPaths(data) {
    log('debug', 'extractBase64FromPaths has started')
    const base64Values = [];
    log('alert', `data is ${JSON.stringify(data.Document.Header.Base64Attachments.Base64Xpath)}`)
    const paths = data.Document.Header.Base64Attachments.Base64Xpath.map((path)=>path.trim())
    log('debug', `paths are ${paths}`)
    const fixedPaths = paths.map(path => {
        if (path.charAt(0) === '$') {
            log('debug', `${path} starts with .`)
            path = path.slice(1);
        }
        if (path.charAt(0) === '.') {
			log('debug', `path with $ is ${path}`)
            path = path.slice(1)
        }
        return xpathToJSONPath(path)
    }).filter(path => path !== null && path !== undefined && path !== '')
    log('debug', `fixedPaths are ${fixedPaths}`)
    fixedPaths.forEach(path => {
        const selectedData = selectDataByJsonPath(data, path)
        if(session.parameters.AllowEmpty === "true"){
            if(typeof selectedData === 'object' && Object.keys(selectedData).length === 0){
                base64Values.push({route:path,value:''})
            }
        }
        else if (typeof selectedData === 'string' && isBase64Encoded(selectedData)) {
            if (isPDF(selectedData)) {
                base64Values.push({ route: path, value: selectedData });
            }
        }else{
            base64Values.push({route:path,value:undefined})
        }
    })
    log('debug', `base64Values are ${JSON.stringify(base64Values)}`)
    return base64Values;
}

function selectDataByJsonPath(data, jsonPath) {
    const keys = jsonPath.split('.');
    let current = data;

    for (const key of keys) {
        log('debug', `key is ${key}`)
        if (current && typeof current === 'object' && current.hasOwnProperty(key)) {
            current = current[key];
        } else {
            log('alert', `Couldn't find mentioned file ${jsonPath}`)
        } // Return undefined if the key is not found.(removed to block message)

    }

    return current;
}


const avRequest = async (avRequestData, path) => {
    log('debug', 'Antivirus section has been started ');
    log('debug', `Checking ${path}`)
    log('debug', `avRequestData is ${JSON.stringify(avRequestData)}`)
    const response = await util.promisify((avRequestData, callback) => urlopen.open(avRequestData, callback))(avRequestData);
    log('debug', `response is ${JSON.stringify(response)}`)
    // Server Returns 500 when error
    // if (response.statusCode !== 200) {
    //     throw new Error(`Error: ${response.statusCode}`);
    // }
    const data = await util.promisify((response, callback) => response.readAsJSON(callback))(response);
    log('debug', `data is ${JSON.stringify(data)}`)
    if (!data) {
        throw new Error(`Error failed fetching data from ${avRequestData.target}`);
    }
    if (data.result !== 0) {
        log('alert', `${path} - Status: ${data.status} Result: ${data.result} CDR: ${data.cdr} Description: ${data.description}`)
        throw new Error('Error rejected by AV');
    }
    log('debug', 'Anti-Virus section has ended');
    return data;
};

const calculateTimeout = (rawfileSize) => {
    const fileSize = rawfileSize
    switch (true) {
        case fileSize <= 50000 && fileSize > 100000:
            return 120
        case fileSize <= 100000 && fileSize > 200000:
            return 180
        case fileSize > 200000:
            return 240
        default:
            return 60
    }
}

const main = async () => {
    log('debug', '# A New request was recieved - Anti-Virus script started')
    const rawBody = session.input;
    let rawParsedBody, body, type;
    try {
        rawParsedBody = await util.promisify((rawBody, callback) => rawBody.readAsXML(callback))(rawBody);
        if (!rawParsedBody) {
            throw new Error('no XML body');
        }
        body = fixBadger(converter.toJSON('badgerfish', XML.parse(XML.stringify(rawParsedBody))))
        type = 'XML';
    } catch (error) {
        log('alert', 'error in parsing body')
        log('debug', `error is ${error}`)
        throw new Error('body is not xml')
    }
    if (!body || body === '{}') {
        throw new Error('no body');
    }
    const avRequestData = {
        target: avUrl,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'apiKey': 'a01665c67c2d4c878cd99b5d41a34efe',
            downloadonsuccess: true
        },
        data: {
            filename: Date.now().toString() + '.pdf',
            file: undefined
        }
    };
    const base64Values = extractBase64FromPaths(body);
    if (base64Values.find((item) => item.value === undefined)) {
        const failed = base64Values.find((item) => item.value === undefined)
        throw new Error(`${failed.route} is not base64`)
    }
    log('debug', `found ${base64Values.length} base64 values`);
    for (let i = 0; i < base64Values.length; i++) {
        avRequestData.data.file = base64Values[i].value;
		if (base64Values[i].value)
        avRequestData.timeout = calculateTimeout(avRequestData.data.file.length)
        log('debug', `Timeout is set to ${avRequestData.timeout}`)
        const avResponse = await avRequest(avRequestData, base64Values[i].route)
        log('debug', `Status is ${avResponse.status} Result is ${avResponse.result} CDR is ${avResponse.cdr} Description is ${avResponse.description}`)
        if (avResponse.result !== 0) {
            throw new Error('Error rejected by AV');
        }
        if (avResponse.cdr === true) {
            log('debug', 'cdr is true')
            log('debug', `body is ${JSON.stringify(body)}`)
            const route = base64Values[i].route;
            const routeArray = route.split('.');
            let obj = body;
            for (let i = 0; i < routeArray.length - 1; i++) {
                obj = obj[routeArray[i]];
            }
            obj[routeArray[routeArray.length - 1]] = avResponse.cdrfile;
        }
    }
    log('debug', '!# The new request was processed - Anti-Virus script ended')
    return session.output.write(rawBody);
};

main()
    .catch(error => {
        log('error', error)
        return session.reject(error.message);
    });
