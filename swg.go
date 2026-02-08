// Package swg provides an HTTPS MITM proxy for content filtering.
//
// The proxy intercepts HTTPS connections using dynamically generated
// certificates signed by a trusted CA. This allows inspection and
// filtering of encrypted traffic.
//
// Basic usage:
//
//	// Load or generate CA certificate
//	cm, err := swg.NewCertManager("ca.crt", "ca.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create and configure proxy
//	proxy := swg.NewProxy(":8080", cm)
//
//	// Add domain filter
//	filter := swg.NewDomainFilter()
//	filter.AddDomain("blocked-site.com")
//	filter.AddDomain("*.ads.example.com")
//	proxy.Filter = filter
//
//	// Start proxy
//	log.Fatal(proxy.ListenAndServe())
package swg
