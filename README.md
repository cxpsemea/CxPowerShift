This is a basic powershell module to use the checkmarxOne REST API. It does not do much so far but is just a start.

- create, get, delete applications
- create, get, delete projects
- run Git scans
- get & delete scans
- update results in a scan

There are two examples included in this repo:
 - cxps_example_gitscan.ps1 creates a project and runs a scan, then deletes the scan and project
 - cxps_example_sast2cx1.ps1 takes a CxSAST XML report and updates a Cx1 scan results (severity, state, and comment) according to the report
 