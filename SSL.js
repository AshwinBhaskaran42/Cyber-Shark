function verifySSL() {
    var url = document.getElementById('url').value;
    var outputDiv = document.getElementById('output');
  
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          var cert = xhr.getResponseHeader('X-SSL-Certificate');
          if (cert) {
            var certInfo = parseCert(cert);
            outputDiv.innerHTML = `The SSL certificate for ${url} is issued by ${certInfo.issuerCommonName}.<br>`;
            outputDiv.innerHTML += `Issuer information:<br>`;
            outputDiv.innerHTML += certInfo.issuerInfo;
          } else {
            outputDiv.textContent = `The SSL certificate for ${url} is not issued by any trustworthy issuer.`;
          }
        } else {
          console.error('Request failed. Status:', xhr.status);
        }
      }
    };
  
    xhr.open('HEAD', url);
    xhr.send();
  
    return false;
  }
  
  function parseCert(cert) {
    var certInfo = {};
    var lines = cert.split(/\r?\n/);
  
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.indexOf('issuer=') === 0) {
        certInfo.issuerInfo = line.substr(7);
        var matches = certInfo.issuerInfo.match(/CN=([^,]+)/);
        if (matches) {
          certInfo.issuerCommonName = matches[1];
        }
      }
    }
  
    return certInfo;
  }
  