import asyncio
import aiohttp
import aiodns
import argparse
import logging
import random
from tqdm import tqdm
from aiohttp import ClientSession, ClientTimeout
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MAX_CONCURRENT_REQUESTS = 10  # Adjusted for stability
RETRY_LIMIT = 3  # Retry limit for failed DNS resolutions

# Semaphore for controlling the concurrency
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

async def fetch_status(session: ClientSession, url: str) -> int:
    try:
        async with session.get(url) as response:
            return response.status
    except Exception as e:
        logger.debug(f"Failed to fetch {url}: {e}")
        return None

async def resolve_subdomain(resolver, subdomain):
    retries = 0
    while retries < RETRY_LIMIT:
        try:
            await semaphore.acquire()
            logger.debug(f"Attempting to resolve {subdomain}")
            await resolver.query(subdomain, 'A')
            return True
        except aiodns.error.DNSError as e:
            if e.args[0] in {4, 5, 2}:
                break  # NXDOMAIN, NoAnswer, NoNameservers
            retries += 1
            backoff = 2 ** retries + random.uniform(0, 1)  # Exponential backoff
            logger.debug(f"DNS error {e.args[1]} resolving {subdomain}, retrying {retries}/{RETRY_LIMIT} in {backoff:.2f}s")
            await asyncio.sleep(backoff)
        except Exception as e:
            logger.error(f"Error resolving {subdomain}: {e}")
            break
        finally:
            semaphore.release()
    return False

async def check_subdomain(subdomain: str, session: ClientSession, resolver) -> dict:
    if await resolve_subdomain(resolver, subdomain):
        url = f"http://{subdomain}"
        status = await fetch_status(session, url)
        return {
            "Subdomain": subdomain,
            "Status": status if status else "Unreachable"
        }
    return None

async def main(domain: str, wordlist_file: str) -> None:
    # Read the wordlist file
    with open(wordlist_file, 'r') as file:
        subdomains = [line.strip() + '.' + domain for line in file]

    # Initialize progress bar
    progress_bar = tqdm(total=len(subdomains), desc='Scanning Subdomains', unit='subdomains')

    # Set up DNS resolver
    resolver = aiodns.DNSResolver()

    # Use aiohttp to perform asynchronous HTTP requests
    timeout = ClientTimeout(total=120)  # Adjusted timeout
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [check_subdomain(subdomain, session, resolver) for subdomain in subdomains]

        results = []
        for f in asyncio.as_completed(tasks):
            result = await f
            if result:
                results.append(result)
            progress_bar.update(1)

    progress_bar.close()

    # Display results in a table format
    if results:
        print(tabulate(results, headers="keys", tablefmt="grid"))
    else:
        logger.info("No subdomains found or reachable.")

    # Summary
    logger.info("Subdomain enumeration completed.")
    if args.output:
        with open(args.output, 'w') as f:
            for result in results:
                f.write(f"{result['Subdomain']} (Status: {result['Status']})\n")
        logger.info(f"Results saved to {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain to enumerate subdomains for.")
    parser.add_argument("wordlist", help="Path to the wordlist file.")
    parser.add_argument("--output", help="File to save found subdomains.", default=None)
    parser.add_argument("--concurrency", help="Number of concurrent requests.", type=int, default=MAX_CONCURRENT_REQUESTS)
    args = parser.parse_args()

    # Update concurrency if specified
    if args.concurrency:
        MAX_CONCURRENT_REQUESTS = args.concurrency
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    try:
        asyncio.run(main(args.domain, args.wordlist))
    except KeyboardInterrupt:
        logger.info("Process interrupted by user. Exiting gracefully...")

