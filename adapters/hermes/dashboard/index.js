/**
 * Glance surfaces pane.
 *
 * A CLASSIC script, not an ES module. The dashboard loads plugin bundles with
 * a plain `<script src>` (see web_server.serve_plugin_asset), so a top-level
 * `export` here is a SyntaxError and the pane never registers. It must also
 * live inside `dashboard/`: the asset route serves only from the plugin's
 * dashboard directory and blocks traversal, so a file one level up is
 * unreachable by design.
 *
 * React comes from the host SDK rather than being bundled, and there is no
 * build step, so the tree is written with React.createElement rather than JSX.
 *
 * Polls GET /stats, which is a cache read. It does NOT poll POST /scan on a
 * timer: that would be a full disk rescan every interval, per open window.
 * Scanning is behind the button.
 */
(function () {
  "use strict";

  var API = "/api/plugins/glance-surfaces";
  var POLL_MS = 30000;

  var registry = window.__HERMES_PLUGINS__;
  var sdk = window.__HERMES_PLUGIN_SDK__;
  if (!registry || !sdk || !sdk.React) return;

  var React = sdk.React;
  var h = React.createElement;
  var useState = sdk.hooks.useState;
  var useEffect = sdk.hooks.useEffect;
  var useCallback = sdk.hooks.useCallback;

  // Host-provided fetch: handles auth in both loopback and gated modes.
  // Plugins must not hand-read window.__HERMES_SESSION_TOKEN__.
  var fetchJSON = sdk.fetchJSON;

  /**
   * Palette assigned by index over whatever categories the API reports, which
   * the API takes from the scanner's own exported CATEGORIES. Exhaustive by
   * construction: a category added in the scanner arrives with a slot already
   * assigned, and there is no second list here to forget to update.
   */
  var SWATCHES = [
    "var(--accent-1, var(--color-accent, currentColor))",
    "var(--accent-2, var(--color-info, currentColor))",
    "var(--accent-3, var(--color-success, currentColor))",
    "var(--accent-4, var(--color-warning, currentColor))",
    "var(--accent-5, var(--color-danger, currentColor))",
    "var(--accent-6, var(--color-muted, currentColor))"
  ];

  var SEVERITY_COLOR = {
    critical: "var(--color-danger, var(--color-error, currentColor))",
    high: "var(--color-warning, var(--color-danger, currentColor))",
    medium: "var(--color-info, var(--color-muted, currentColor))",
    info: "var(--color-muted, currentColor)"
  };

  function categoryColor(categories, name) {
    var i = categories.indexOf(name);
    if (i < 0) return "var(--color-muted, currentColor)";
    return SWATCHES[i % SWATCHES.length];
  }

  function GlancePane() {
    var s = useState(null);
    var stats = s[0];
    var setStats = s[1];
    var b = useState(false);
    var busy = b[0];
    var setBusy = b[1];

    var load = useCallback(function () {
      return fetchJSON(API + "/stats").then(setStats, function () {
        setStats({ unreachable: true });
      });
    }, []);

    useEffect(function () {
      load();
      var t = setInterval(load, POLL_MS);
      return function () {
        clearInterval(t);
      };
    }, [load]);

    if (!stats) return h("p", null, "Loading Glance...");
    if (stats.unreachable) return h("p", null, "Glance: stats unavailable.");

    var categories = stats.categories || [];
    var counts = stats.counts || {};
    var kids = [];

    kids.push(h("h3", { key: "t" }, "Agent surfaces"));

    if (!stats.scanner_available) {
      kids.push(
        h(
          "p",
          { key: "na", style: { color: SEVERITY_COLOR.high } },
          "glance-scanner is not on PATH. Nothing is being scanned."
        )
      );
    }

    kids.push(
      h(
        "p",
        { key: "when", style: { color: "var(--color-muted, currentColor)" } },
        stats.scanned_at
          ? "Scanned " + stats.total_scanned + " surfaces at " + stats.scanned_at +
            " under policy " + (stats.policy || "strict") + "."
          : "No scan yet."
      )
    );

    kids.push(
      h(
        "div",
        { key: "counts", style: { display: "flex", gap: "1rem", flexWrap: "wrap" } },
        ["critical", "high", "medium", "info"].map(function (sev) {
          return h(
            "span",
            { key: sev, style: { color: SEVERITY_COLOR[sev] } },
            sev + " " + (counts[sev] || 0)
          );
        })
      )
    );

    if (stats.baselined) {
      kids.push(
        h(
          "p",
          { key: "base", style: { color: "var(--color-muted, currentColor)" } },
          stats.baselined + " finding(s) baselined at first run and not reported."
        )
      );
    }

    (stats.warnings || []).forEach(function (w, i) {
      kids.push(
        h("p", { key: "w" + i, style: { color: SEVERITY_COLOR.medium } }, w.message || "")
      );
    });

    if (stats.last_error) {
      kids.push(
        h(
          "p",
          { key: "err", style: { color: SEVERITY_COLOR.high } },
          "Last error: " + stats.last_error
        )
      );
    }

    kids.push(
      categories.length
        ? h(
            "div",
            {
              key: "legend",
              style: { display: "flex", gap: "0.75rem", flexWrap: "wrap", fontSize: "0.85em" }
            },
            categories.map(function (c) {
              return h("span", { key: c, style: { color: categoryColor(categories, c) } }, c);
            })
          )
        : h(
            "p",
            { key: "legend", style: { color: "var(--color-muted, currentColor)" } },
            "Category list unavailable: glance-scanner was not found on PATH."
          )
    );

    kids.push(
      h(
        "button",
        {
          key: "scan",
          type: "button",
          disabled: busy || stats.scanning,
          style: { marginTop: "0.75rem" },
          onClick: function () {
            setBusy(true);
            fetchJSON(API + "/scan", { method: "POST" })
              .catch(function () {})
              .then(function () {
                setBusy(false);
                load();
              });
          }
        },
        busy || stats.scanning ? "Scanning..." : "Scan now"
      )
    );

    return h("div", null, kids);
  }

  registry.register("glance-surfaces", GlancePane);
})();
