festum.rs
==========

file existence checker for trailing services

* VirusBay
* VirusTotal (set apikey to `$VTAPIKEY`)
* MalShare (set apikey to `$MALSHARE_APIKEY`)
* reverse.it (set apikey to `$REVIT_APIKEY`)
* AlienVault OTX (set apikey to `$OTX_APIKEY`)

```rust
// use environment variables as default api key
let cli = festum::Client::default(); 

// please note that this function ignores all services that has no api key.
let res = cli.query("a hash");
println!("{:?}", res);
```

