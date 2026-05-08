async function loadFlows() {

    const response = await fetch("../flows/flows.json");
    const flows = await response.json();

    const container = document.getElementById(
        "sequence-container"
    );

    container.innerHTML = "";

    flows.reverse().forEach(flow => {

        const row = document.createElement("div");
        row.className = "sequence";

        row.innerHTML = `
            <div class="node">
                <div><strong>Browser</strong></div>
            </div>

            <div class="arrow"></div>

            <div class="node">
                <div class="method">
                    ${flow.method || flow.status}
                </div>
                <div>${flow.path}</div>
                <small>${flow.host}</small>
            </div>

            <div class="arrow"></div>

            <div class="node">
                <div><strong>SSR Server</strong></div>
            </div>
        `;

        container.appendChild(row);
    });
}

loadFlows();

setInterval(loadFlows, 2000);