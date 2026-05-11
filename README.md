# ATT&CK Mapper

**APT Behavior to MITRE ATT&CK Technique Mapping Tool**

ATT&CK Mapper is a dynamic mapping engine that translates adversary behaviors and tactics into MITRE ATT&CK framework techniques and tactics. It provides automated threat behavior classification with detection coverage analysis.

## Quick Start

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ATT&CK_Mapper
   ```

2. **Open in browser**
   - Open `index.html` directly in a web browser
   - No build process or dependencies required

3. **Optional: Local server (for smooth CORS handling)**
   ```bash
   # Python 3
   python -m http.server 8000
   
   # Node.js (npm)
   npx http-server
   ```
   Then navigate to `http://localhost:8000`

## About Flow Mapping

ATT&CK Mapper implements a three-tier mapping framework:

```
APT Action Input
    ↓
[Auto-Translation Layer] → Converts Vietnamese to English via Google Translate API
    ↓
[Keyword Matching Layer] → Matches against MITRE ATT&CK technique descriptions
    ↓
[Technique Resolution] → Maps to T-codes, extracts Tactic classification
    ↓
[Detection Coverage] → Links detection rules and log sources
    ↓
Results Matrix Display
```

The system maintains three data sources:
- **STIX Data** (Enterprise ATT&CK v14.1): Official MITRE framework techniques and tactics
- **Detection Rules Database**: Custom detection rules linked to techniques
- **Log Source Map**: Available detection tools and their log source coverage

## How It Works

### Input Processing

1. **User enters APT behaviors** (one action per line):
   - Natural language descriptions of adversary actions
   - Supports Vietnamese and English
   - Examples: "Dump password from LSASS using Mimikatz", "Create scheduled task for persistence"

2. **Automatic translation**
   - Vietnamese text is translated to English
   - Translation cache (3-tier: memory → localStorage → API) minimizes API calls
   - Non-Latin text is properly handled

3. **Behavior classification**
   - Each action is matched against MITRE ATT&CK technique descriptions
   - Alias index enables fast keyword matching
   - Results ranked by relevance score

### Mapping Output

Results are presented as an interactive matrix showing:

| Column | Description |
|--------|-------------|
| Behavior | Mapped APT action |
| T-Code | MITRE ATT&CK technique identifier |
| Technique | Full technique name |
| Tactic | Tactic classification (Initial Access, Execution, Persistence, etc.) |
| Detection | Available detection tools and rules |

### Detection Coverage

For each mapped technique, the tool displays:
- **Available tools**: Log sources that can detect this technique
- **Detection rules**: Custom rules (if configured in database)
- **Coverage status**: Indicates whether detection rules are available

Color coding:
- **Green badge**: Tool has both log coverage AND detection rules
- **Blue badge**: Tool has log coverage (rules may be added later)
- **Gray badge**: Tool available but no detection coverage configured

## Usage Guide

### Basic Workflow

1. **Enter adversary behaviors**
   - Type or paste APT actions in the input area
   - One action per line for best results
   - Mix Vietnamese and English as needed

2. **Click "Mapping" button**
   - System processes input and generates mapping
   - Translation and matching happen automatically
   - Results appear in real-time

3. **Review results matrix**
   - View all mapped techniques
   - Statistics panel shows total actions, unique techniques, tactics, and available rules

4. **Filter by tactic** (optional)
   - Use Tactic filter pills above results
   - "All" shows complete mapping

5. **Examine detection coverage**
   - Click detection badges to view available tools
   - Check which detection methods support each technique

### Advanced Features

- **Matrix view**: Click "Show Matrix" to see techniques in MITRE ATT&CK grid format
- **Search**: Use search box to find specific APT groups or techniques
- **Clear results**: Use "Clear" button to reset and start new mapping

## Technical Architecture

### Core Components

- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3
- **Data Processing**: Dynamic technique matching and alias indexing
- **External APIs**: MITRE STIX 2.1 (via GitHub raw CDN), Google Translate API
- **Storage**: JSON-based detection rules and log source configuration

### Key Features

- **Translation Caching**: Reduces API dependency for repeated translations
- **Alias Indexing**: Fast keyword matching using inverted index structure
- **Responsive Design**: Optimized for desktop and mobile viewing
- **Modular Architecture**: Separation of concerns for maintainability

## Data Files

- `data/stix.json` - MITRE ATT&CK framework data (auto-downloaded)
- `data/rules_db.json` - Technique-to-rule mappings
- `data/log_source_map.json` - Detection tool and log source definitions
- `data/detection_rules_db.json` - Custom detection rule details
- `data/keyword_aliases.json` - Alternative keywords for technique matching

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Requires JavaScript enabled
- Requires localStorage support (for translation caching)

## Dependencies

All dependencies are loaded via CDN or are local:
- Font Awesome 6.5.0 (icons)
- Google Fonts (typography)
- Google Translate API (optional, for Vietnamese translation)

No package manager or build tools required.

## Performance

- Initial load: ~2-3 seconds (STIX data fetch from GitHub)
- Mapping 10 behaviors: ~500ms average
- Translation cache reduces subsequent queries to <100ms

## Limitations

- STIX data must be downloaded on first load
- Dependent on Google Translate API for non-English input
- Detection rules coverage depends on configured database

## Use Cases

- **Threat Assessment**: Classify adversary behaviors using standardized framework
- **Red Team Planning**: Map attack scenarios to ATT&CK techniques for exercise design
- **Detection Engineering**: Identify gaps in detection coverage for specific tactics
- **Security Training**: Educational mapping of threat behaviors to frameworks

---

**Version**: 1.0  
**Last Updated**: May 2026  
**MITRE ATT&CK Version**: Enterprise 14.1
