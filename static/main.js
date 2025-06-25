
                const socket = io();

            // Handle form submission
            document.getElementById('enumForm').addEventListener('submit', function(e) {
                e.preventDefault();
                // Gather form data
                let params = {
                    domain: document.getElementById('domain').value.trim(),
                    passive: document.getElementById('passive').checked,
                    active: document.getElementById('active').checked,
                    brute: document.getElementById('brute').checked,
                    tld: document.getElementById('tld').checked,
                    verbose: document.getElementById('verbose').checked,
                    // File uploads are not sent via socket.io directly; handle separately if needed
                };
                //document.getElementById('results').innerHTML = "<b>Enumeration started...</b>";
                if (params.domain) {
                    // Emit the enumeration request
                    socket.emit('start_enum', params);
                }else {
                    alert("Please enter a domain to enumerate.");
                }
            });

            // Listen for partial updates
            socket.on('enum_update', function(data) {
                let resultsDiv = document.getElementById('resultsContent');
                // Clear previous results if this is the first update
                if (resultsDiv.innerHTML === "<b>Enumeration started...</b>") {
                    resultsDiv.innerHTML = "";
                }
                // Append the new result
                
                resultsDiv.innerHTML += `<div><b>${data.step}:</b> <pre>${JSON.stringify(data, null, 2)}</pre></div>`;
            });
            socket.on('enum_complete', function(data) {
                let resultsDiv = document.getElementById('resultsContent');
                const results = data.result;

                // Helper to pretty-print each step
                function renderStep(step, value) {
                    if (typeof value === 'object' && value !== null) {
                        // For objects (like brute-force results), make a nested list
                        let html = `<ul>`;
                        for (const key in value) {
                            if (Array.isArray(value[key])) {
                                html += `<li><b>${key}:</b> <span style="color: #007bff;">${value[key].join(', ')}</span></li>`;
                            } else if (typeof value[key] === 'object') {
                                html += `<li><b>${key}:</b> ${renderStep('', value[key])}</li>`;
                            } else {
                                html += `<li><b>${key}:</b> <span>${value[key]}</span></li>`;
                            }
                        }
                        html += `</ul>`;
                        return html;
                    } else {
                        return `<span>${value}</span>`;
                    }
                }

                let html = `<div class="mt-3"><b>All Results:</b>`;
                if (results && typeof results === 'object') {
                    for (const step in results) {
                        html += `<div style="margin-top:10px;"><b style="color:#28a745;">${step}</b>: ${renderStep(step, results[step])}</div>`;
                    }
                } else {
                    html += `<pre>${JSON.stringify(results, null, 2)}</pre>`;
                }
                html += `</div>`;

                resultsDiv.innerHTML += html;
            });
            socket.on('enum_message', function(data) {
                // Show the message to the user, e.g.:
                alert(data.message);
                // Or display in a custom div
            });
