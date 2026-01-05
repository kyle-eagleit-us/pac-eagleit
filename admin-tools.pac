function FindProxyForURL(url, host) {
  host = host.toLowerCase();

  // Azure forward proxy reachable over WireGuard
  var PROXY = "PROXY 10.254.0.1:3128";
  var DIRECT = "DIRECT";

  function hostMatches(domain) {
    // Exact match or any subdomain match
    if (host === domain) return true;
    return dnsDomainIs(host, "." + domain);
  }

  // Microsoft admin portals + required auth/static endpoints to avoid sign-in loops
  var microsoftAdminDomains = [
    // Admin portals
    "admin.microsoft.com",
    "entra.microsoft.com",
    "portal.azure.com",

    // Core auth and supporting endpoints
    "login.microsoftonline.com",
    "microsoftonline.com",
    "msauth.net",
    "msauthimages.net",
    "aadcdn.msftauth.net",
    "office.com",
    "office.net"
  ];

  // Your admin tools
  var adminToolDomains = [
    // SuperOps
    "support.eagleit.us",

    // Hudu
    "eagleit.huducloud.com",

    // Cloudflare Dashboard
    "dash.cloudflare.com",

    // EasyDMARC
    "easydmarc.com",

    // 1Password Web
    "eagleit.1password.com"
  ];

  // Route Microsoft admin + auth/support domains through proxy
  for (var i = 0; i < microsoftAdminDomains.length; i++) {
    if (hostMatches(microsoftAdminDomains[i])) {
      return PROXY;
    }
  }

  // DUO: strictly admin-*.duosecurity.com only
  if (dnsDomainIs(host, ".duosecurity.com")) {
    if (host.substring(0, 6) === "admin-") {
      return PROXY;
    }
    return DIRECT;
  }

  // Route your admin tools through proxy
  for (var j = 0; j < adminToolDomains.length; j++) {
    if (hostMatches(adminToolDomains[j])) {
      return PROXY;
    }
  }

  // Default: direct internet access
  return DIRECT;
}
