(function () {
    "use strict";

    var data = { upstreams: [], virtual_hosts: [], routes: [] };

    // --- Init ---
    document.addEventListener("DOMContentLoaded", function () {
        loadTheme();
        fetchData();
        document.getElementById("add-upstream-btn").addEventListener("click", addUpstream);
        document.getElementById("add-vhost-btn").addEventListener("click", addVhost);
        document.getElementById("add-route-btn").addEventListener("click", addDefaultRoute);
        document.getElementById("save-routing-btn").addEventListener("click", saveAll);
    });

    function fetchData() {
        fetch("/api/v1/routing")
            .then(function (r) { return r.json(); })
            .then(function (d) {
                data = d;
                render();
            })
            .catch(function (e) { toast("Failed to load: " + e, true); });
    }

    function render() {
        renderUpstreams();
        renderVhosts();
        renderDefaultRoutes();
    }

    // =========================================================================
    // Upstreams
    // =========================================================================

    function renderUpstreams() {
        var c = document.getElementById("upstreams-container");
        while (c.firstChild) c.removeChild(c.firstChild);

        for (var i = 0; i < data.upstreams.length; i++) {
            c.appendChild(buildUpstreamCard(i));
        }
        if (data.upstreams.length === 0) {
            var p = document.createElement("p");
            p.style.cssText = "color:var(--text-muted);font-size:.85rem";
            p.textContent = "No upstreams configured. Add one to get started.";
            c.appendChild(p);
        }
    }

    function buildUpstreamCard(idx) {
        var us = data.upstreams[idx];
        var card = document.createElement("div");
        card.className = "upstream-card";

        // Header
        var head = document.createElement("div");
        head.className = "upstream-card-head";
        var h3 = document.createElement("h3");
        h3.textContent = us.name || "upstream-" + idx;
        head.appendChild(h3);
        var delBtn = el("button", "btn btn--danger btn--sm", "Delete");
        delBtn.addEventListener("click", function () { data.upstreams.splice(idx, 1); render(); });
        head.appendChild(delBtn);
        card.appendChild(head);

        // Name
        card.appendChild(fieldRow("Name", "text", us.name || "", function (v) {
            data.upstreams[idx].name = v;
            h3.textContent = v || "upstream-" + idx;
        }, "my-backend"));

        // Strategy
        var stratRow = document.createElement("div");
        stratRow.className = "field-row";
        var stratLabel = el("label", "", "Strategy");
        stratRow.appendChild(stratLabel);
        var stratSel = document.createElement("select");
        ["round_robin", "weighted", "least_conn", "ip_hash"].forEach(function (s) {
            var opt = document.createElement("option");
            opt.value = s; opt.textContent = s;
            if (us.load_balancer === s) opt.selected = true;
            stratSel.appendChild(opt);
        });
        stratSel.addEventListener("change", function () { data.upstreams[idx].load_balancer = this.value; });
        stratRow.appendChild(stratSel);
        card.appendChild(stratRow);

        // Targets header
        var tgtHead = document.createElement("div");
        tgtHead.style.cssText = "display:flex;align-items:center;justify-content:space-between;margin-top:1rem;margin-bottom:.5rem";
        var tgtLabel = el("span", "", "Targets");
        tgtLabel.style.cssText = "font-weight:600;font-size:.9rem";
        tgtHead.appendChild(tgtLabel);
        card.appendChild(tgtHead);

        // Targets
        var targets = us.targets || [];
        for (var t = 0; t < targets.length; t++) {
            card.appendChild(buildTargetItem(idx, t));
        }

        // Add target
        var addRow = document.createElement("div");
        addRow.className = "add-input-row";
        var addInp = document.createElement("input");
        addInp.type = "text";
        addInp.placeholder = "http://backend:3000";
        addRow.appendChild(addInp);
        var addBtn = el("button", "btn btn--primary btn--sm", "+ Add Target");
        addBtn.addEventListener("click", function () {
            if (!addInp.value.trim()) return;
            if (!data.upstreams[idx].targets) data.upstreams[idx].targets = [];
            data.upstreams[idx].targets.push({ url: addInp.value.trim(), weight: 1 });
            addInp.value = "";
            render();
        });
        addRow.appendChild(addBtn);
        card.appendChild(addRow);

        return card;
    }

    function buildTargetItem(upIdx, tgtIdx) {
        var tgt = data.upstreams[upIdx].targets[tgtIdx];
        var item = document.createElement("div");
        item.className = "target-item";

        var urlInp = document.createElement("input");
        urlInp.type = "text";
        urlInp.value = tgt.url || "";
        urlInp.addEventListener("input", function () { data.upstreams[upIdx].targets[tgtIdx].url = this.value; });
        item.appendChild(urlInp);

        var wl = el("span", "w-label", "w:");
        item.appendChild(wl);

        var wInp = document.createElement("input");
        wInp.type = "number";
        wInp.className = "target-weight";
        wInp.min = "1"; wInp.max = "100";
        wInp.value = tgt.weight || 1;
        wInp.addEventListener("change", function () { data.upstreams[upIdx].targets[tgtIdx].weight = parseInt(this.value) || 1; });
        item.appendChild(wInp);

        var xBtn = el("button", "btn btn--danger btn--sm", "\u00d7");
        xBtn.addEventListener("click", function () { data.upstreams[upIdx].targets.splice(tgtIdx, 1); render(); });
        item.appendChild(xBtn);

        return item;
    }

    function addUpstream() {
        data.upstreams.push({ name: "new-upstream", load_balancer: "round_robin", targets: [], health_check: { enabled: false } });
        render();
    }

    // =========================================================================
    // Virtual Hosts
    // =========================================================================

    function renderVhosts() {
        var c = document.getElementById("vhosts-container");
        while (c.firstChild) c.removeChild(c.firstChild);

        var vhs = data.virtual_hosts || [];
        for (var i = 0; i < vhs.length; i++) {
            c.appendChild(buildVhostCard(i));
        }
        if (vhs.length === 0) {
            var p = document.createElement("p");
            p.style.cssText = "color:var(--text-muted);font-size:.85rem";
            p.textContent = "No virtual hosts. All traffic uses default routes below.";
            c.appendChild(p);
        }
    }

    function buildVhostCard(idx) {
        var vh = data.virtual_hosts[idx];
        var card = document.createElement("div");
        card.className = "upstream-card";

        // Header
        var head = document.createElement("div");
        head.className = "upstream-card-head";
        var h3 = document.createElement("h3");
        h3.textContent = (vh.domains && vh.domains[0]) || "new-domain";
        head.appendChild(h3);
        var delBtn = el("button", "btn btn--danger btn--sm", "Delete");
        delBtn.addEventListener("click", function () { data.virtual_hosts.splice(idx, 1); render(); });
        head.appendChild(delBtn);
        card.appendChild(head);

        // Domains
        var domLabel = el("span", "", "Domains");
        domLabel.style.cssText = "font-weight:600;font-size:.9rem;display:block;margin-bottom:.4rem";
        card.appendChild(domLabel);

        var chips = document.createElement("div");
        chips.className = "domain-chips";
        var domains = vh.domains || [];
        for (var d = 0; d < domains.length; d++) {
            chips.appendChild(buildDomainChip(idx, d, domains[d]));
        }
        card.appendChild(chips);

        // Add domain
        var addRow = document.createElement("div");
        addRow.className = "add-input-row";
        var addInp = document.createElement("input");
        addInp.type = "text";
        addInp.placeholder = "api.example.com";
        addRow.appendChild(addInp);
        var addBtn = el("button", "btn btn--primary btn--sm", "+ Domain");
        addBtn.addEventListener("click", function () {
            if (!addInp.value.trim()) return;
            if (!data.virtual_hosts[idx].domains) data.virtual_hosts[idx].domains = [];
            data.virtual_hosts[idx].domains.push(addInp.value.trim());
            addInp.value = "";
            render();
        });
        addRow.appendChild(addBtn);
        card.appendChild(addRow);

        // Routes
        var rtLabel = el("span", "", "Routes");
        rtLabel.style.cssText = "font-weight:600;font-size:.9rem;display:block;margin-top:1rem;margin-bottom:.5rem";
        card.appendChild(rtLabel);

        var routes = vh.routes || [];
        for (var r = 0; r < routes.length; r++) {
            card.appendChild(buildRouteItem(idx, r, true));
        }

        var addRtBtn = el("button", "btn btn--sm", "+ Route");
        addRtBtn.style.marginTop = ".4rem";
        addRtBtn.addEventListener("click", function () {
            if (!data.virtual_hosts[idx].routes) data.virtual_hosts[idx].routes = [];
            data.virtual_hosts[idx].routes.push({ path: "/", upstream: "", strip_prefix: false });
            render();
        });
        card.appendChild(addRtBtn);

        return card;
    }

    function buildDomainChip(vhIdx, dIdx, domain) {
        var chip = document.createElement("span");
        chip.className = "domain-chip";
        var txt = document.createElement("span");
        txt.textContent = domain;
        chip.appendChild(txt);
        var xBtn = document.createElement("button");
        xBtn.textContent = "\u00d7";
        xBtn.addEventListener("click", function () {
            data.virtual_hosts[vhIdx].domains.splice(dIdx, 1);
            render();
        });
        chip.appendChild(xBtn);
        return chip;
    }

    function addVhost() {
        if (!data.virtual_hosts) data.virtual_hosts = [];
        data.virtual_hosts.push({ domains: [], tls: {}, routes: [{ path: "/", upstream: "" }] });
        render();
    }

    // =========================================================================
    // Route Items (shared between vhosts and default routes)
    // =========================================================================

    function buildRouteItem(parentIdx, routeIdx, isVhost) {
        var route = isVhost ? data.virtual_hosts[parentIdx].routes[routeIdx] : data.routes[routeIdx];
        var item = document.createElement("div");
        item.className = "route-item";

        var pathInp = document.createElement("input");
        pathInp.type = "text";
        pathInp.value = route.path || "/";
        pathInp.placeholder = "/api";
        pathInp.addEventListener("input", function () {
            if (isVhost) data.virtual_hosts[parentIdx].routes[routeIdx].path = this.value;
            else data.routes[routeIdx].path = this.value;
        });
        item.appendChild(pathInp);

        var arrow = el("span", "arrow", "\u2192");
        item.appendChild(arrow);

        var sel = document.createElement("select");
        var emptyOpt = document.createElement("option");
        emptyOpt.value = ""; emptyOpt.textContent = "-- select upstream --";
        sel.appendChild(emptyOpt);
        for (var u = 0; u < data.upstreams.length; u++) {
            var opt = document.createElement("option");
            opt.value = data.upstreams[u].name;
            opt.textContent = data.upstreams[u].name;
            if (route.upstream === data.upstreams[u].name) opt.selected = true;
            sel.appendChild(opt);
        }
        sel.addEventListener("change", function () {
            if (isVhost) data.virtual_hosts[parentIdx].routes[routeIdx].upstream = this.value;
            else data.routes[routeIdx].upstream = this.value;
        });
        item.appendChild(sel);

        var xBtn = el("button", "btn btn--danger btn--sm", "\u00d7");
        xBtn.addEventListener("click", function () {
            if (isVhost) data.virtual_hosts[parentIdx].routes.splice(routeIdx, 1);
            else data.routes.splice(routeIdx, 1);
            render();
        });
        item.appendChild(xBtn);

        return item;
    }

    // =========================================================================
    // Default Routes
    // =========================================================================

    function renderDefaultRoutes() {
        var c = document.getElementById("routes-container");
        while (c.firstChild) c.removeChild(c.firstChild);

        var rts = data.routes || [];
        for (var i = 0; i < rts.length; i++) {
            c.appendChild(buildRouteItem(0, i, false));
        }
        if (rts.length === 0) {
            var p = document.createElement("p");
            p.style.cssText = "color:var(--text-muted);font-size:.85rem";
            p.textContent = "No default routes configured.";
            c.appendChild(p);
        }
    }

    function addDefaultRoute() {
        if (!data.routes) data.routes = [];
        data.routes.push({ path: "/", upstream: "" });
        render();
    }

    // =========================================================================
    // Save
    // =========================================================================

    function saveAll() {
        var status = document.getElementById("rt-status");
        status.textContent = "Saving...";

        fetch("/api/v1/routing", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
        .then(function (res) {
            if (res.ok) {
                toast("Routing saved and proxy rebuilt!", false);
                status.textContent = "Saved successfully";
                fetchData();
            } else {
                toast("Error: " + (res.data.error || "Failed"), true);
                status.textContent = "Save failed";
            }
        })
        .catch(function (err) {
            toast("Network error: " + err, true);
            status.textContent = "Save failed";
        });
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text) e.textContent = text;
        return e;
    }

    function fieldRow(label, type, value, onChange, placeholder) {
        var row = document.createElement("div");
        row.className = "field-row";
        var lbl = el("label", "", label);
        row.appendChild(lbl);
        var inp = document.createElement("input");
        inp.type = type;
        inp.value = value;
        if (placeholder) inp.placeholder = placeholder;
        inp.style.flex = "1";
        inp.addEventListener("input", function () { onChange(this.value); });
        row.appendChild(inp);
        return row;
    }

    function toast(msg, isError) {
        var t = document.createElement("div");
        t.className = "toast " + (isError ? "toast--err" : "toast--ok");
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(function () { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(function () { t.remove(); }, 300); }, 3000);
    }

    // --- Theme ---
    window.toggleTheme = function () {
        var cur = document.documentElement.getAttribute("data-theme");
        var next = cur === "light" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("gwaf-theme", next);
        var btn = document.getElementById("theme-btn");
        if (btn) btn.textContent = next === "light" ? "\u263E" : "\u2606";
    };
    function loadTheme() {
        var saved = localStorage.getItem("gwaf-theme");
        if (saved) {
            document.documentElement.setAttribute("data-theme", saved);
            var btn = document.getElementById("theme-btn");
            if (btn) btn.textContent = saved === "light" ? "\u263E" : "\u2606";
        }
    }
})();
