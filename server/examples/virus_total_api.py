import asyncio
import pprint

from server.services.data_collectors import VirusTotalCollector

async def get_virus_total_data(hash_val):
    collector = VirusTotalCollector()
    result = await collector.get_file_report(hash_val)
    pprint.pprint(result)

hash_val = "5d7cb1a2ca7db04edf23dd3ed41125c8c867b0ad"
ans = asyncio.run(get_virus_total_data(hash_val))
pprint.pprint(ans)