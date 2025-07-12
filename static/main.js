
        const socket = io();
        document.getElementById('inputType').addEventListener('change', function() {
            if (this.value === 'domain') {
                document.getElementById('domainInputDiv').style.display = '';
                document.getElementById('ptrInputDiv').style.display = 'none';
                document.getElementById('enumOptionsRow').style.display = '';
            } else {
                document.getElementById('domainInputDiv').style.display = 'none';
                document.getElementById('ptrInputDiv').style.display = '';
                document.getElementById('enumOptionsRow').style.display = 'none';
            }
        });
            // Handle form submission
            document.getElementById('enumForm').addEventListener('submit', function(e) {
                e.preventDefault();
                let inputType = document.getElementById('inputType').value;

                // Save checkbox states before enumeration
                const checkboxIds = ['passive', 'active', 'brute', 'doh', 'dot', 'tld', 'verbose', 'graph'];
                const checkboxStates = {};
                checkboxIds.forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        checkboxStates[id] = el.checked;
                    }
                });

                // Gather form data
                document.getElementById('resultsContent').innerHTML = '';
                let params = {
                    inputType: inputType,
                    domain: inputType === 'domain' ? document.getElementById('domain').value.trim() : '',
                    ptr: inputType === 'ptr' ? document.getElementById('ptr').value.trim() : '',

                    passive: checkboxStates['passive'],
                    active: checkboxStates['active'],
                    brute: checkboxStates['brute'],
                    doh: checkboxStates['doh'],
                    dot: checkboxStates['dot'],
                    tld: checkboxStates['tld'],
                    verbose: checkboxStates['verbose'],
                    graph: checkboxStates['graph'],

                    // File uploads are not sent via socket.io directly; handle separately if needed
                };
            
                //document.getElementById('results').innerHTML = "<b>Enumeration started...</b>";
                if ((inputType === 'domain' && params.domain) || (inputType === 'ptr' && params.ptr)) {
                    // Emit the enumeration request
                    socket.emit('start_enum', params);
                }else {
                    alert("Please enter a domain to enumerate.");
                }
            });

            // Listen for partial updates
            socket.on('enum_update', function(data) {
                let resultsDiv = document.getElementById('resultsContent');

                // Special case: if step is 'Starting active DNS probing...' and result is null, show only this in green and clear others
                if (data.step === 'Starting active DNS probing...' && (data.result === null || data.result === undefined)) {
                    resultsDiv.innerHTML = `
                    <div class="alert alert-success" role="alert">
                        ${data.step}
                    </div>
                    `;
                    return;
                }

                // Create a unique id for accordion items based on step
                let safeStep = data.step.replace(/\s+/g, '_').replace(/[^\w\-]/g, '');
                let headingId = `heading_${safeStep}`;
                let collapseId = `collapse_${safeStep}`;

                // Check if an accordion item for this step already exists
                if (!document.getElementById(headingId)) {
                    // Create accordion item HTML
                    let html = `
                    <div class="accordion-item" id="item_${safeStep}">
                        <h2 class="accordion-header" id="${headingId}">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="false" aria-controls="${collapseId}">
                                ${data.step}
                            </button>
                        </h2>
                        <div id="${collapseId}" class="accordion-collapse collapse" aria-labelledby="${headingId}" data-bs-parent="#resultsContent">
                            <div class="accordion-body">
                                <pre class="results-pre" id="pre_${safeStep}">${JSON.stringify(data.result, null, 2)}</pre>
                            </div>
                        </div>
                    </div>
                    `;
                    // Append the new accordion item
                    resultsDiv.insertAdjacentHTML('beforeend', html);
                } else {
                    // Update existing accordion item's pre content
                    let pre = document.getElementById(`pre_${safeStep}`);
                    if (pre) {
                        pre.textContent = JSON.stringify(data.result, null, 2);
                    }
                }
            });

            let latestCompleteResults = null;

            socket.on('enum_complete', function(data) {
                let resultsDiv = document.getElementById('resultsContent');
                const results = data.result;
                latestCompleteResults = results;

                // Clear previous results (including enum_update results)
                resultsDiv.innerHTML = '';

                // Create accordion items for each result step
                let index = 0;
                let html = '';
                if (results && typeof results === 'object') {
                    for (const step in results) {
                        index++;
                        const res = results[step];
                        let safeStep = step.replace(/\s+/g, '_').replace(/[^\w\-]/g, '');
                        let headingId = `heading_complete_${safeStep}_${index}`;
                        let collapseId = `collapse_complete_${safeStep}_${index}`;

                        html += `
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="${headingId}">
                                <button class="accordion-button ${index === 1 ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="${index === 1 ? 'true' : 'false'}" aria-controls="${collapseId}">
                                    ${step}
                                </button>
                            </h2>
                            <div id="${collapseId}" class="accordion-collapse collapse ${index === 1 ? 'show' : ''}" aria-labelledby="${headingId}" data-bs-parent="#resultsContent">
                                <div class="accordion-body">
                                    <pre class="results-pre">${JSON.stringify(res, null, 2)}</pre>
                                </div>
                            </div>
                        </div>
                        `;
                    }
                } else {
                    html = `<pre>${JSON.stringify(results, null, 2)}</pre>`;
                }
                
                resultsDiv.innerHTML = html;
                alert("Enumeration completed successfully!");
                // Enable export button on completion
                const exportBtn = document.getElementById('exportBtn');
                if (exportBtn) {
                    exportBtn.disabled = false;
                }
                // Restore checkbox states after completion
                const checkboxIds = ['passive', 'active', 'brute', 'doh', 'dot', 'tld', 'verbose', 'graph'];
                checkboxIds.forEach(id => {
                    const el = document.getElementById(id);
                    if (el && checkboxStates && checkboxStates.hasOwnProperty(id)) {
                        el.checked = checkboxStates[id];
                    }
                });
            });

            // Export button click handler
            const exportBtn = document.getElementById('exportBtn');
            if (exportBtn) {
                exportBtn.addEventListener('click', function() {
                    if (!latestCompleteResults) {
                        alert('No results to export.');
                        return;
                    }
                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(latestCompleteResults, null, 2));
                    const downloadAnchorNode = document.createElement('a');
                    downloadAnchorNode.setAttribute("href", dataStr);
                    downloadAnchorNode.setAttribute("download", "enumeration_results.json");
                    document.body.appendChild(downloadAnchorNode); // required for firefox
                    downloadAnchorNode.click();
                    downloadAnchorNode.remove();
                });
            }
            socket.on('enum_message', function(data) {
                // Show the message to the user, e.g.:
                alert(data.message);
                // Or display in a custom div
            });
            
            document.getElementById('stopBtn').addEventListener('click', function() {
                socket.emit('stop_enum');
                alert('Enumeration stopped by the user');
            });
