use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};
type GenericResult<T> = Result<T, failure::Error>;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Client {
    virustotal: Option<String>,
    malshare: Option<String>,
    reverseit: Option<String>,
    alienvault: Option<String>,
}

impl Default for Client {
    /// use environment variables as default
    fn default() -> Self {
        Client {
            virustotal: std::env::var("VTAPIKEY").ok(),
            malshare: std::env::var("MALSHARE_APIKEY").ok(),
            alienvault: std::env::var("OTX_APIKEY").ok(),
            reverseit: std::env::var("REVIT_APIKEY").ok(),
        }
    }
}

#[derive(Deserialize)]
struct AlienVaultBaseIndicator {
    id: i64,
}

#[derive(Deserialize)]
struct MalshareResult {
    #[serde(rename="SHA256")]
    sha256: Option<String>,
}

#[derive(Deserialize)]
struct AlienVaultResponse {
    base_indicator: Option<AlienVaultBaseIndicator>,
}

#[derive(Deserialize)]
struct VirusTotalResponse {
    response_code: i64,
}

#[derive(Deserialize)]
struct VirusBaySearchResult {
    search: Vec<VirusBaySearchResultItem>,
}

#[derive(Deserialize)]
struct VirusBaySearchResultItem {
    _id: String,
}

impl Client {
    pub fn query_alienvault(&self, hash: impl AsRef<str>) -> GenericResult<bool> {
        let apikey = self
            .alienvault
            .as_ref()
            .ok_or(failure::err_msg("AlienVault OTX APIKEY not set"))?;
        let res: AlienVaultResponse = reqwest::Client::new()
            .get(
                format!(
                    "https://otx.alienvault.com/api/v1/indicators/file/{}/general",
                    hash.as_ref()
                )
                .as_str(),
            )
            .header("X-OTX-API-KEY", apikey.as_str())
            .send()?
            .json()?;
        Ok(res.base_indicator.is_some())
    }

    pub fn query_virustotal(&self, hash: impl AsRef<str>) -> GenericResult<bool> {
        let apikey = self
            .virustotal
            .as_ref()
            .ok_or(failure::err_msg("VirusTotal APIKEY not set"))?;
        let res: VirusTotalResponse = reqwest::get(
            format!(
                "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
                apikey.as_str(),
                hash.as_ref()
            )
            .as_str(),
        )?
        .json()?;
        Ok(res.response_code == 1)
    }

    pub fn query_malshare(&self, hash: impl AsRef<str>) -> GenericResult<bool> {

        let apikey = self
            .malshare
            .as_ref()
            .ok_or(failure::err_msg("MalShare API key not set"))?;

        let res: MalshareResult = reqwest::get(
            format!(
                "https://malshare.com/api.php?api_key={}&action=details&hash={}",
                apikey.as_str(),
                hash.as_ref()
            )
            .as_str(),
        )?
        .json()?;

        Ok(res.sha256.is_some())
    }

    pub fn query_reverseit(&self, hash: impl AsRef<str>) -> GenericResult<bool> {
        let apikey = self
            .reverseit
            .as_ref()
            .ok_or(failure::err_msg("credentials for reverse.it not set"))?;

        let status = reqwest::Client::new()
            .get(format!("https://www.reverse.it/api/v2/overview/{}", hash.as_ref(),).as_str())
            .header(USER_AGENT, "Falcon Sandbox")
            .header("api-key", apikey.as_str())
            .send()?
            .status();

        Ok(status.is_success())
    }

    pub fn query_virusbay(&self, hash: impl AsRef<str>) -> GenericResult<bool> {
        let res: VirusBaySearchResult = reqwest::get(
            format!("https://beta.virusbay.io/sample/search?q={}", hash.as_ref()).as_str(),
        )?
        .json()?;
        Ok(!res.search.is_empty())
    }

    pub fn query(&self, hash: impl AsRef<str>) -> QueryResult {
        let hash = hash.as_ref();
        QueryResult {
            virustotal: self.query_virustotal(hash).unwrap_or(false),
            virusbay: self.query_virusbay(hash).unwrap_or(false),
            malshare: self.query_malshare(hash).unwrap_or(false),
            alienvault: self.query_alienvault(hash).unwrap_or(false),
            reverseit: self.query_reverseit(hash).unwrap_or(false),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResult {
    pub virustotal: bool,
    pub virusbay: bool,
    pub malshare: bool,
    pub reverseit: bool,
    pub alienvault: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query() {
        let cli = Client::default();
        assert_eq!(
            true,
            cli.query_alienvault(
                "da6a59c5a1be831489b0890c1ed3247c922a0940d1a6b332a4f73ca83807d440"
            )
            .unwrap(),
        );
        assert_eq!(
            true,
            cli.query_virustotal(
                "a3ecfa709230537c28fd0c24d49ff549c83e146aede4fe345b61db3509dd4180"
            )
            .unwrap()
        );
        assert_eq!(
            true,
            cli.query_malshare("4fe84640bf5521aaaa67b4bde37d3771")
                .unwrap()
        );
        assert_eq!(
            true,
            cli.query_reverseit("9ce3ee6b5142ab88146e54b91be9c2a1db72305019de44076556721ff7686eb1")
                .unwrap()
        );
    }
}
