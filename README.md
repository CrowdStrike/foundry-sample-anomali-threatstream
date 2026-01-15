![CrowdStrike Falcon](/images/cs-logo.png?raw=true)

# Anomali ThreatStream sample Foundry app

The Anomali ThreatStream sample Foundry app is a community-driven, open source project which serves as an example of an app which can be built using CrowdStrike's Foundry ecosystem. `foundry-sample-anomali-threatstream` is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

This app is one of several App Templates included in Foundry that you can use to jumpstart your development. It comes complete with a set of preconfigured capabilities aligned to its business purpose. Deploy this app from the Templates page with a single click in the Foundry UI, or create an app from this template using the CLI.

> [!IMPORTANT]
> To view documentation and deploy this sample app, you need access to the Falcon console.

## Description

Automates threat intelligence ingestion from Anomali ThreatStream, synchronizing IOCs (IPs, domains, URLs, email addresses, file hashes) hourly as CSV lookup files for Falcon Next-Gen SIEM detection and hunting workflows.

## Prerequisites

* The Foundry CLI (instructions below).
* Python 3.13+ (needed if modifying the app's function). See [Python For Beginners](https://www.python.org/about/gettingstarted/) for installation instructions.

### Install the Foundry CLI

You can install the Foundry CLI with Scoop on Windows or Homebrew on Linux/macOS.

**Windows**:

Install [Scoop](https://scoop.sh/). Then, add the Foundry CLI bucket and install the Foundry CLI.

```shell
scoop bucket add foundry https://github.com/crowdstrike/scoop-foundry-cli.git
scoop install foundry
```

Or, you can download the [latest Windows zip file](https://assets.foundry.crowdstrike.com/cli/latest/foundry_Windows_x86_64.zip), expand it, and add the install directory to your PATH environment variable.

**Linux and macOS**:

Install [Homebrew](https://docs.brew.sh/Installation). Then, add the Foundry CLI repository to the list of formulae that Homebrew uses and install the CLI:

```shell
brew tap crowdstrike/foundry-cli
brew install crowdstrike/foundry-cli/foundry
```

Run `foundry version` to verify it's installed correctly.

## Getting Started

Clone this sample to your local system, or [download as a zip file](https://github.com/CrowdStrike/foundry-sample-anomali-threatstream/archive/refs/heads/main.zip) and import it into Foundry.

```shell
git clone https://github.com/CrowdStrike/foundry-sample-anomali-threatstream
cd foundry-sample-anomali-threatstream
```

Log in to Foundry:

```shell
foundry login
```

Select the following permissions:

- [ ] Create and run RTR scripts
- [x] Create, execute and test workflow templates
- [x] Create, run and view API integrations
- [ ] Create, edit, delete, and list queries

Deploy the app:

```shell
foundry apps deploy
```

> [!TIP]
> If you get an error that the name already exists, change the name to something unique to your CID in `manifest.yml`.

Once the deployment has finished, you can release the app:

```shell
foundry apps release
```

Next, go to **Foundry** > **App catalog**, find your app, and install it. During installation, you'll be prompted to configure the Anomali ThreatStream API integration with your credentials (API key format: `email:key`). After installation, go to **Fusion SOAR** > **Workflows** to see the scheduled workflow from this app.

## About this sample app

This app includes:

- **Foundry Function**: `anomali-ioc-ingest` - A memory-efficient Python function that ingests IOC data from Anomali ThreatStream and creates CSV lookup files for Falcon Next-Gen SIEM using disk-based streaming (O(1) memory usage)
- **API Integration**: Anomali ThreatStream API configuration for authentication and data retrieval
- **Collections**:
  - `ingest_jobs` - Tracks each job run for ingesting IOCs
  - `update_id_tracker` - Tracks the update_id from Anomali ThreatStream API for incremental sync
- **Workflow**: Scheduled workflow that automatically runs the ingest function hourly to keep threat intelligence up to date

Key features:

- **Memory-Efficient Streaming**: Disk-based CSV processing with O(1) memory usage, enabling 200MB file processing with ~3-5MB constant memory overhead
- **200 MB File Size Protection**: Detects when files approach NGSIEM upload limit and provides actionable filtering guidance
- **Fail-Fast Estimation**: Optional early file size projection to prevent hours of pagination when dataset exceeds limits
- **Automated IOC Ingestion**: Hourly synchronization of threat intelligence with workflow-managed pagination
- **Multiple IOC Types**: IP addresses, domains, URLs, email addresses, file hashes (MD5/SHA1/SHA256)
- **Incremental Sync**: Efficient processing using update_id tracking with type-specific state management
- **Missing File Recovery**: Automatically recreates deleted lookup files on next run
- **Early Termination**: Intelligent pagination stops when no new unique IOCs are found
- **Secure Integration**: API-based authentication (no hardcoded credentials)
- **Comprehensive Testing**: Extensive unit tests with 90%+ code coverage, stress testing scripts, and workflow simulation

## Development

### Local Development Setup

1. **Create and activate virtual environment**:
   ```bash
   cd functions/anomali-ioc-ingest
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt --upgrade pip
   ```

### Running Tests

**Unit Tests**: The project includes comprehensive unit tests:
```bash
python -m pytest test_main.py -v
```

**Test with Coverage**: Generate coverage reports (requires pytest-cov):
```bash
pip install pytest-cov
python -m pytest test_main.py --cov=main --cov-report=html
# View coverage report: open htmlcov/index.html
```

### Code Quality

**Pylint**: Run static code analysis (configuration in `.pylintrc`):
```bash
python -m pylint main.py
```

### Debugging Functions Locally

**Environment Variables**: Set up required environment variables for local testing:
```bash
export APP_ID="your-app-id"
export FALCON_CLIENT_ID="your-client-id"  # Must have CustomStorage read/write scopes
export FALCON_CLIENT_SECRET="your-client-secret"
```

**Run the function**:
```bash
python main.py
```

## Additional Documentation

📖 **[App Documentation](app_docs/README.md)** - Complete setup instructions, usage, and threat intelligence queries

## Foundry resources

- Foundry documentation: [US-1](https://falcon.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [US-2](https://falcon.us-2.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [EU](https://falcon.eu-1.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry)
- Foundry learning resources: [US-1](https://falcon.crowdstrike.com/foundry/learn) | [US-2](https://falcon.us-2.crowdstrike.com/foundry/learn) | [EU](https://falcon.eu-1.crowdstrike.com/foundry/learn)

---

<p align="center"><img src="/images/cs-logo-footer.png"><br/><img width="300px" src="/images/adversary-goblin-panda.png"></p>
<h3><p align="center">WE STOP BREACHES</p></h3>
