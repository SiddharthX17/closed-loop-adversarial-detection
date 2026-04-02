from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.plugins import InstalledSigmaPlugins

plugins = InstalledSigmaPlugins.autodiscover()
pipeline = plugins.pipelines["sysmon"]()  # or however it's instantiated

backend = sqliteBackend(processing_pipeline=pipeline)

rule_yaml = """
title: Test
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'encoded'
    condition: selection
"""

rule = SigmaCollection.from_yaml(rule_yaml)
sql = backend.convert(rule)
print(sql)
