
# """
# Solana Meme Coin Scout Bot

# A monitoring bot that scans the Solana blockchain for newly launched meme coins,
# classifies them based on on-chain metrics, and logs the findings.

# This is a read-only implementation that does not perform any transactions.
# """

# import json
# import time
# import logging
# import asyncio
# import datetime
# from typing import Dict, List, Any, Optional, Tuple

# import requests
# from solana.rpc.async_api import AsyncClient
# from solders.pubkey import Pubkey  # Updated from solana.publickey.PublicKey
# from solders.transaction import Transaction  # Updated from solana.transaction.Transaction
# from solders.signature import Signature

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler("logs/scout_bot.log"),  # Updated path to match config
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger("SolanaMemeScout")

# # Constants
# SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
# TOKEN_METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
# SOLSCAN_API_URL = "https://api.solscan.io/v2"
# RPC_ENDPOINT = "https://api.mainnet-beta.solana.com"
# SLEEP_INTERVAL = 60  # seconds between scans

# # Risk thresholds
# RISK_THRESHOLDS = {
#     "green": {
#         "min_holders": 50,
#         "min_transactions": 100,
#         "max_creator_ownership_pct": 40
#     },
#     "yellow": {
#         "min_holders": 20,
#         "min_transactions": 30,
#         "max_creator_ownership_pct": 70
#     }
#     # Below yellow thresholds will be classified as "red"
# }

# class SolanaMemeScout:
#     def __init__(self, rpc_endpoint: str = RPC_ENDPOINT):
#         self.client = AsyncClient(rpc_endpoint)
#         self.tracked_tokens = {}
#         self.load_tracked_tokens()
#         logger.info("Solana Meme Scout Bot initialized")

#     def load_tracked_tokens(self) -> None:
#         """Load previously tracked tokens from disk."""
#         try:
#             with open('data/tracked_tokens.json', 'r') as f:  # Updated path to match config
#                 self.tracked_tokens = json.load(f)
#                 logger.info(f"Loaded {len(self.tracked_tokens)} previously tracked tokens")
#         except FileNotFoundError:
#             logger.info("No existing tracked tokens file found, starting fresh")
#             self.tracked_tokens = {}

#     def save_tracked_tokens(self) -> None:
#         """Save tracked tokens to disk."""
#         with open('data/tracked_tokens.json', 'w') as f:  # Updated path to match config
#             json.dump(self.tracked_tokens, f, indent=2)
#         logger.info(f"Saved {len(self.tracked_tokens)} tracked tokens to disk")

#     async def get_recent_token_creations(self, limit: int = 20) -> List[Dict[str, Any]]:
#         """
#         Get recently created tokens on Solana by looking for SPL Token Program transactions.
#         """
#         logger.info(f"Scanning for {limit} recent token creations...")
#         new_tokens = []
        
#         try:
#             # Get recent signatures for the SPL Token Program
#             resp = await self.client.get_signatures_for_address(
#                 Pubkey.from_string(SPL_TOKEN_PROGRAM_ID),  # Updated from PublicKey
#                 limit=limit
#             )
            
#             if not resp.value:
#                 logger.warning("No recent SPL token signatures found")
#                 return new_tokens
                
#             # Process each transaction to find token creations
#             for sig_info in resp.value:
#                 signature = sig_info.signature
                
#                 # Get the transaction details
#                 tx_details = await self.client.get_transaction(
#                     signature, 
#                     max_supported_transaction_version=0
#                 )
                
#                 if not tx_details.value:
#                     continue
                    
#                 # Check if this is a token creation (CreateAccount or InitializeMint instruction)
#                 if self._is_token_creation(tx_details.value):
#                     token_data = self._extract_token_data(tx_details.value)
#                     if token_data:
#                         new_tokens.append(token_data)
                        
#             logger.info(f"Found {len(new_tokens)} potential new tokens")
#             return new_tokens
            
#         except Exception as e:
#             logger.error(f"Error retrieving recent token creations: {str(e)}")
#             return []

#     def _is_token_creation(self, tx_data: Dict) -> bool:
#         """
#         Determine if a transaction contains token creation instructions.
        
#         This is a simplified implementation - in a production environment, you would
#         want to decode the transaction instructions in detail.
#         """
#         # This is a simplified check - look for patterns in logs that suggest token creation
#         if tx_data.get("meta") and tx_data["meta"].get("logMessages"):
#             logs = tx_data["meta"]["logMessages"]
#             # Look for token initialization logs
#             return any("InitializeMint" in log for log in logs)
#         return False

#     def _extract_token_data(self, tx_data: Dict) -> Optional[Dict]:
#         """
#         Extract relevant token data from a transaction.
        
#         In a production environment, you would parse the transaction instructions
#         and decode the data properly.
#         """
#         try:
#             if not tx_data.get("meta") or not tx_data.get("transaction"):
#                 return None
                
#             logs = tx_data["meta"].get("logMessages", [])
            
#             # Extract token mint address (simplified approach)
#             token_address = None
#             creator_address = None
            
#             # Get the mint account from logs (simplified - would need proper parsing)
#             for log in logs:
#                 if "Mint" in log and "initialized" in log:
#                     # Simplified extraction - would need proper parsing in production
#                     parts = log.split()
#                     for part in parts:
#                         if len(part) > 30 and part.isalnum():  # Potential Solana address
#                             token_address = part
#                             break
            
#             # Get the transaction creator
#             if tx_data.get("transaction") and tx_data["transaction"].get("message"):
#                 if tx_data["transaction"]["message"].get("accountKeys"):
#                     creator_address = tx_data["transaction"]["message"]["accountKeys"][0]
            
#             if not token_address:
#                 return None
                
#             # Basic token data
#             token_data = {
#                 "token_address": token_address,
#                 "creator_address": creator_address,
#                 "created_at": datetime.datetime.now().isoformat(),
#                 "creation_transaction": tx_data.get("transaction", {}).get("signatures", [""])[0],
#                 "metadata": self._get_token_metadata(token_address)
#             }
            
#             return token_data
            
#         except Exception as e:
#             logger.error(f"Error extracting token data: {str(e)}")
#             return None

#     def _get_token_metadata(self, token_address: str) -> Dict:
#         """
#         Attempt to get token metadata from Solscan API.
        
#         In a production system, you might want to use multiple data sources.
#         """
#         metadata = {
#             "name": "Unknown",
#             "symbol": "UNKNOWN",
#             "decimals": 9,  # Default for most Solana tokens
#             "supply": "Unknown"
#         }
        
#         try:
#             # Use Solscan API to get token metadata
#             headers = {
#                 "Accept": "application/json",
#                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#             }
#             response = requests.get(
#                 f"{SOLSCAN_API_URL}/token/meta?token={token_address}",
#                 headers=headers
#             )
            
#             if response.status_code == 200:
#                 data = response.json()
#                 if data.get("data"):
#                     token_data = data["data"]
#                     metadata.update({
#                         "name": token_data.get("name", "Unknown"),
#                         "symbol": token_data.get("symbol", "UNKNOWN"),
#                         "decimals": token_data.get("decimals", 9),
#                         "supply": token_data.get("supply", "Unknown")
#                     })
                    
#             return metadata
            
#         except Exception as e:
#             logger.error(f"Error fetching token metadata: {str(e)}")
#             return metadata

#     async def analyze_token(self, token_address: str) -> Dict:
#         """
#         Analyze a token by gathering holder information and transaction activity.
        
#         Returns a dict with risk classification and analysis data.
#         """
#         logger.info(f"Analyzing token {token_address}")
        
#         # Initialize analysis data
#         analysis = {
#             "token_address": token_address,
#             "analyzed_at": datetime.datetime.now().isoformat(),
#             "holders_count": 0,
#             "transaction_count": 0,
#             "creator_ownership_pct": 0,
#             "risk_category": "red"  # Default to high risk
#         }
        
#         try:
#             # Get holder count (using Solscan API)
#             holders = await self._get_token_holders(token_address)
#             analysis["holders_count"] = len(holders)
            
#             # Get transaction count (simplified - would use proper API in production)
#             tx_count = await self._get_token_transaction_count(token_address)
#             analysis["transaction_count"] = tx_count
            
#             # Estimate creator ownership percentage (simplified)
#             if holders and len(holders) > 0:
#                 # Assume first holder is creator in this simplified implementation
#                 top_holder = holders[0]
#                 analysis["creator_ownership_pct"] = float(top_holder.get("amount", 0)) / float(top_holder.get("total_supply", 1)) * 100
            
#             # Classify risk
#             analysis["risk_category"] = self._classify_risk(
#                 analysis["holders_count"],
#                 analysis["transaction_count"],
#                 analysis["creator_ownership_pct"]
#             )
            
#             return analysis
            
#         except Exception as e:
#             logger.error(f"Error analyzing token {token_address}: {str(e)}")
#             return analysis

#     async def _get_token_holders(self, token_address: str) -> List[Dict]:
#         """Get token holders using Solscan API."""
#         holders = []
#         try:
#             headers = {
#                 "Accept": "application/json",
#                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#             }
            
#             response = requests.get(
#                 f"{SOLSCAN_API_URL}/token/holders?token={token_address}&limit=20",
#                 headers=headers
#             )
            
#             if response.status_code == 200:
#                 data = response.json()
#                 if data.get("data") and data["data"].get("result"):
#                     holders = data["data"]["result"]
                    
#             return holders
            
#         except Exception as e:
#             logger.error(f"Error fetching token holders: {str(e)}")
#             return []

#     async def _get_token_transaction_count(self, token_address: str) -> int:
#         """Get token transaction count (simplified)."""
#         try:
#             # Use Solscan API to get transaction count
#             headers = {
#                 "Accept": "application/json",
#                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#             }
            
#             response = requests.get(
#                 f"{SOLSCAN_API_URL}/token/txs?token={token_address}&limit=1",
#                 headers=headers
#             )
            
#             if response.status_code == 200:
#                 data = response.json()
#                 # Extract total count from response
#                 return data.get("data", {}).get("total", 0)
                
#             return 0
            
#         except Exception as e:
#             logger.error(f"Error fetching token transaction count: {str(e)}")
#             return 0

#     def _classify_risk(self, holders_count: int, transaction_count: int, creator_ownership_pct: float) -> str:
#         """Classify token risk based on on-chain metrics."""
#         # Check if metrics meet green thresholds
#         green_thresholds = RISK_THRESHOLDS["green"]
#         if (holders_count >= green_thresholds["min_holders"] and
#             transaction_count >= green_thresholds["min_transactions"] and
#             creator_ownership_pct <= green_thresholds["max_creator_ownership_pct"]):
#             return "green"
            
#         # Check if metrics meet yellow thresholds
#         yellow_thresholds = RISK_THRESHOLDS["yellow"]
#         if (holders_count >= yellow_thresholds["min_holders"] and
#             transaction_count >= yellow_thresholds["min_transactions"] and
#             creator_ownership_pct <= yellow_thresholds["max_creator_ownership_pct"]):
#             return "yellow"
            
#         # Default to red (high risk)
#         return "red"

#     def generate_report(self) -> str:
#         """Generate a report of tracked tokens and their risk classifications."""
#         report = []
#         report.append("=" * 80)
#         report.append(f"SOLANA MEME COIN SCOUT REPORT - {datetime.datetime.now().isoformat()}")
#         report.append("=" * 80)
        
#         # Group tokens by risk category
#         green_tokens = []
#         yellow_tokens = []
#         red_tokens = []
        
#         for token_addr, token_data in self.tracked_tokens.items():
#             token_name = token_data.get("metadata", {}).get("name", "Unknown")
#             token_symbol = token_data.get("metadata", {}).get("symbol", "UNKNOWN")
#             risk = token_data.get("analysis", {}).get("risk_category", "red")
            
#             token_summary = f"{token_name} ({token_symbol}) - {token_addr[:8]}...{token_addr[-6:]}"
            
#             if risk == "green":
#                 green_tokens.append(token_summary)
#             elif risk == "yellow":
#                 yellow_tokens.append(token_summary)
#             else:
#                 red_tokens.append(token_summary)
        
#         # Add tokens to report by risk category
#         report.append(f"\nLOW RISK TOKENS (GREEN): {len(green_tokens)}")
#         report.append("-" * 40)
#         for token in green_tokens:
#             report.append(f"✅ {token}")
        
#         report.append(f"\nMEDIUM RISK TOKENS (YELLOW): {len(yellow_tokens)}")
#         report.append("-" * 40)
#         for token in yellow_tokens:
#             report.append(f"⚠️ {token}")
        
#         report.append(f"\nHIGH RISK TOKENS (RED): {len(red_tokens)}")
#         report.append("-" * 40)
#         for token in red_tokens:
#             report.append(f"🔴 {token}")
        
#         report.append("\n" + "=" * 80)
        
#         return "\n".join(report)

#     async def run(self, scan_interval: int = SLEEP_INTERVAL, max_iterations: Optional[int] = None) -> None:
#         """
#         Run the scout bot main loop.
        
#         Args:
#             scan_interval: Time in seconds between scans
#             max_iterations: Maximum number of scan iterations (None for infinite)
#         """
#         logger.info(f"Starting Solana Meme Scout Bot (scan interval: {scan_interval}s)")
        
#         iteration = 0
#         while max_iterations is None or iteration < max_iterations:
#             iteration += 1
#             logger.info(f"Starting scan iteration {iteration}")
            
#             try:
#                 # Get recent token creations
#                 new_tokens = await self.get_recent_token_creations(limit=20)
                
#                 # Analyze new tokens
#                 for token_data in new_tokens:
#                     token_address = token_data.get("token_address")
                    
#                     # Skip if already tracked
#                     if token_address in self.tracked_tokens:
#                         continue
                        
#                     # Analyze the token
#                     analysis = await self.analyze_token(token_address)
                    
#                     # Store token with analysis
#                     token_data["analysis"] = analysis
#                     self.tracked_tokens[token_address] = token_data
                    
#                     logger.info(f"New token found: {token_data.get('metadata', {}).get('name')} " +
#                                 f"({token_data.get('metadata', {}).get('symbol')}) - " +
#                                 f"Risk: {analysis.get('risk_category', 'unknown')}")
                
#                 # Save tracked tokens to disk
#                 self.save_tracked_tokens()
                
#                 # Generate and log report every 5 iterations
#                 if iteration % 5 == 0:
#                     report = self.generate_report()
#                     logger.info("\n" + report)
                    
#                     # Save report to file
#                     with open(f"reports/report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w") as f:  # Updated path to match config
#                         f.write(report)
                
#                 # Sleep until next iteration
#                 logger.info(f"Scan iteration {iteration} complete. Sleeping for {scan_interval} seconds...")
#                 await asyncio.sleep(scan_interval)
                
#             except Exception as e:
#                 logger.error(f"Error in scan iteration {iteration}: {str(e)}")
#                 await asyncio.sleep(scan_interval)

# async def main():
#     """Main entry point for the Solana Meme Scout Bot."""
#     bot = SolanaMemeScout()
#     await bot.run()

# if __name__ == "__main__":
#     asyncio.run(main())

#!/usr/bin/env python3
"""
Solana Meme Coin Scout Bot

A monitoring bot that scans the Solana blockchain for newly launched meme coins,
classifies them based on on-chain metrics, and logs the findings.

This is a read-only implementation that does not perform any transactions.
"""

import json
import time
import logging
import asyncio
import datetime
from typing import Dict, List, Any, Optional, Tuple

import requests
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey  # Updated from solana.publickey.PublicKey
from solders.transaction import Transaction  # Updated from solana.transaction.Transaction
from solders.signature import Signature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/scout_bot.log"),  # Updated path to match config
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SolanaMemeScout")

# Constants
SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
SOLSCAN_API_URL = "https://api.solscan.io/v2"
RPC_ENDPOINT = "https://api.mainnet-beta.solana.com"
SLEEP_INTERVAL = 60  # seconds between scans

# Risk thresholds
RISK_THRESHOLDS = {
    "green": {
        "min_holders": 50,
        "min_transactions": 100,
        "max_creator_ownership_pct": 40
    },
    "yellow": {
        "min_holders": 20,
        "min_transactions": 30,
        "max_creator_ownership_pct": 70
    }
    # Below yellow thresholds will be classified as "red"
}

class SolanaMemeScout:
    def __init__(self, rpc_endpoint: str = RPC_ENDPOINT):
        self.client = AsyncClient(rpc_endpoint)
        self.tracked_tokens = {}
        self.load_tracked_tokens()
        logger.info("Solana Meme Scout Bot initialized")

    def load_tracked_tokens(self) -> None:
        """Load previously tracked tokens from disk."""
        try:
            with open('data/tracked_tokens.json', 'r') as f:  # Updated path to match config
                self.tracked_tokens = json.load(f)
                logger.info(f"Loaded {len(self.tracked_tokens)} previously tracked tokens")
        except FileNotFoundError:
            logger.info("No existing tracked tokens file found, starting fresh")
            self.tracked_tokens = {}

    def save_tracked_tokens(self) -> None:
        """Save tracked tokens to disk."""
        with open('data/tracked_tokens.json', 'w') as f:  # Updated path to match config
            json.dump(self.tracked_tokens, f, indent=2)
        logger.info(f"Saved {len(self.tracked_tokens)} tracked tokens to disk")

    async def get_recent_token_creations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recently created tokens on Solana by looking for SPL Token Program transactions.
        """
        logger.info(f"Scanning for {limit} recent token creations...")
        new_tokens = []
        
        try:
            # Get recent signatures for the SPL Token Program
            resp = await self.client.get_signatures_for_address(
                Pubkey.from_string(SPL_TOKEN_PROGRAM_ID),  # Updated from PublicKey
                limit=limit
            )
            
            if not resp.value:
                logger.warning("No recent SPL token signatures found")
                return new_tokens
                
            # Process each transaction to find token creations
            for sig_info in resp.value:
                signature = sig_info.signature
                
                # Get the transaction details
                tx_details = await self.client.get_transaction(
                    signature, 
                    max_supported_transaction_version=0
                )
                
                if not tx_details.value:
                    continue
                    
                # Check if this is a token creation (CreateAccount or InitializeMint instruction)
                if self._is_token_creation(tx_details.value):
                    token_data = self._extract_token_data(tx_details.value)
                    if token_data:
                        new_tokens.append(token_data)
                        
            logger.info(f"Found {len(new_tokens)} potential new tokens")
            return new_tokens
            
        except Exception as e:
            logger.error(f"Error retrieving recent token creations: {str(e)}")
            return []

    def _is_token_creation(self, tx_data) -> bool:
        """
        Determine if a transaction contains token creation instructions.
        
        This is a simplified implementation - in a production environment, you would
        want to decode the transaction instructions in detail.
        """
        try:
            # Access the log messages via attributes instead of dictionary access
            if hasattr(tx_data, "meta") and tx_data.meta is not None:
                log_messages = tx_data.meta.log_messages
                if log_messages:
                    # Look for token initialization logs
                    return any("InitializeMint" in log for log in log_messages)
            # Fall back to dictionary access if attribute access doesn't work
            elif isinstance(tx_data, dict) and tx_data.get("meta") and tx_data["meta"].get("logMessages"):
                logs = tx_data["meta"]["logMessages"]
                # Look for token initialization logs
                return any("InitializeMint" in log for log in logs)
        except Exception as e:
            logger.error(f"Error checking for token creation: {str(e)}")
        return False

    def _extract_token_data(self, tx_data) -> Optional[Dict]:
        """
        Extract relevant token data from a transaction.
        
        In a production environment, you would parse the transaction instructions
        and decode the data properly.
        """
        try:
            token_address = None
            creator_address = None
            logs = []
            
            # Try to handle both object and dictionary formats
            if hasattr(tx_data, "meta") and hasattr(tx_data.meta, "log_messages"):
                logs = tx_data.meta.log_messages
            elif isinstance(tx_data, dict) and "meta" in tx_data and "logMessages" in tx_data["meta"]:
                logs = tx_data["meta"]["logMessages"]
            else:
                return None
                
            # Get the mint account from logs (simplified - would need proper parsing)
            for log in logs:
                if "Mint" in log and "initialized" in log:
                    # Simplified extraction - would need proper parsing in production
                    parts = log.split()
                    for part in parts:
                        if len(part) > 30 and part.isalnum():  # Potential Solana address
                            token_address = part
                            break
            
            # Get the transaction creator - try both object and dictionary formats
            if hasattr(tx_data, "transaction") and hasattr(tx_data.transaction, "message"):
                if hasattr(tx_data.transaction.message, "account_keys") and tx_data.transaction.message.account_keys:
                    creator_address = str(tx_data.transaction.message.account_keys[0])
            elif isinstance(tx_data, dict) and "transaction" in tx_data and "message" in tx_data["transaction"]:
                if "accountKeys" in tx_data["transaction"]["message"]:
                    creator_address = tx_data["transaction"]["message"]["accountKeys"][0]
            
            if not token_address:
                return None
                
            # Prepare creation_transaction value
            creation_tx = ""
            if hasattr(tx_data, "transaction") and hasattr(tx_data.transaction, "signatures"):
                creation_tx = str(tx_data.transaction.signatures[0])
            elif isinstance(tx_data, dict) and "transaction" in tx_data and "signatures" in tx_data["transaction"]:
                creation_tx = tx_data["transaction"]["signatures"][0]
                
            # Basic token data
            token_data = {
                "token_address": token_address,
                "creator_address": creator_address,
                "created_at": datetime.datetime.now().isoformat(),
                "creation_transaction": creation_tx,
                "metadata": self._get_token_metadata(token_address)
            }
            
            return token_data
            
        except Exception as e:
            logger.error(f"Error extracting token data: {str(e)}")
            return None

    def _get_token_metadata(self, token_address: str) -> Dict:
        """
        Attempt to get token metadata from Solscan API.
        
        In a production system, you might want to use multiple data sources.
        """
        metadata = {
            "name": "Unknown",
            "symbol": "UNKNOWN",
            "decimals": 9,  # Default for most Solana tokens
            "supply": "Unknown"
        }
        
        try:
            # Use Solscan API to get token metadata
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(
                f"{SOLSCAN_API_URL}/token/meta?token={token_address}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("data"):
                    token_data = data["data"]
                    metadata.update({
                        "name": token_data.get("name", "Unknown"),
                        "symbol": token_data.get("symbol", "UNKNOWN"),
                        "decimals": token_data.get("decimals", 9),
                        "supply": token_data.get("supply", "Unknown")
                    })
                    
            return metadata
            
        except Exception as e:
            logger.error(f"Error fetching token metadata: {str(e)}")
            return metadata

    async def analyze_token(self, token_address: str) -> Dict:
        """
        Analyze a token by gathering holder information and transaction activity.
        
        Returns a dict with risk classification and analysis data.
        """
        logger.info(f"Analyzing token {token_address}")
        
        # Initialize analysis data
        analysis = {
            "token_address": token_address,
            "analyzed_at": datetime.datetime.now().isoformat(),
            "holders_count": 0,
            "transaction_count": 0,
            "creator_ownership_pct": 0,
            "risk_category": "red"  # Default to high risk
        }
        
        try:
            # Get holder count (using Solscan API)
            holders = await self._get_token_holders(token_address)
            analysis["holders_count"] = len(holders)
            
            # Get transaction count (simplified - would use proper API in production)
            tx_count = await self._get_token_transaction_count(token_address)
            analysis["transaction_count"] = tx_count
            
            # Estimate creator ownership percentage (simplified)
            if holders and len(holders) > 0:
                # Assume first holder is creator in this simplified implementation
                top_holder = holders[0]
                analysis["creator_ownership_pct"] = float(top_holder.get("amount", 0)) / float(top_holder.get("total_supply", 1)) * 100
            
            # Classify risk
            analysis["risk_category"] = self._classify_risk(
                analysis["holders_count"],
                analysis["transaction_count"],
                analysis["creator_ownership_pct"]
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing token {token_address}: {str(e)}")
            return analysis

    async def _get_token_holders(self, token_address: str) -> List[Dict]:
        """Get token holders using Solscan API."""
        holders = []
        try:
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = requests.get(
                f"{SOLSCAN_API_URL}/token/holders?token={token_address}&limit=20",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("data") and data["data"].get("result"):
                    holders = data["data"]["result"]
                    
            return holders
            
        except Exception as e:
            logger.error(f"Error fetching token holders: {str(e)}")
            return []

    async def _get_token_transaction_count(self, token_address: str) -> int:
        """Get token transaction count (simplified)."""
        try:
            # Use Solscan API to get transaction count
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = requests.get(
                f"{SOLSCAN_API_URL}/token/txs?token={token_address}&limit=1",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                # Extract total count from response
                return data.get("data", {}).get("total", 0)
                
            return 0
            
        except Exception as e:
            logger.error(f"Error fetching token transaction count: {str(e)}")
            return 0

    def _classify_risk(self, holders_count: int, transaction_count: int, creator_ownership_pct: float) -> str:
        """Classify token risk based on on-chain metrics."""
        # Check if metrics meet green thresholds
        green_thresholds = RISK_THRESHOLDS["green"]
        if (holders_count >= green_thresholds["min_holders"] and
            transaction_count >= green_thresholds["min_transactions"] and
            creator_ownership_pct <= green_thresholds["max_creator_ownership_pct"]):
            return "green"
            
        # Check if metrics meet yellow thresholds
        yellow_thresholds = RISK_THRESHOLDS["yellow"]
        if (holders_count >= yellow_thresholds["min_holders"] and
            transaction_count >= yellow_thresholds["min_transactions"] and
            creator_ownership_pct <= yellow_thresholds["max_creator_ownership_pct"]):
            return "yellow"
            
        # Default to red (high risk)
        return "red"

    def generate_report(self) -> str:
        """Generate a report of tracked tokens and their risk classifications."""
        report = []
        report.append("=" * 80)
        report.append(f"SOLANA MEME COIN SCOUT REPORT - {datetime.datetime.now().isoformat()}")
        report.append("=" * 80)
        
        # Group tokens by risk category
        green_tokens = []
        yellow_tokens = []
        red_tokens = []
        
        for token_addr, token_data in self.tracked_tokens.items():
            token_name = token_data.get("metadata", {}).get("name", "Unknown")
            token_symbol = token_data.get("metadata", {}).get("symbol", "UNKNOWN")
            risk = token_data.get("analysis", {}).get("risk_category", "red")
            
            token_summary = f"{token_name} ({token_symbol}) - {token_addr[:8]}...{token_addr[-6:]}"
            
            if risk == "green":
                green_tokens.append(token_summary)
            elif risk == "yellow":
                yellow_tokens.append(token_summary)
            else:
                red_tokens.append(token_summary)
        
        # Add tokens to report by risk category
        report.append(f"\nLOW RISK TOKENS (GREEN): {len(green_tokens)}")
        report.append("-" * 40)
        for token in green_tokens:
            report.append(f"✅ {token}")
        
        report.append(f"\nMEDIUM RISK TOKENS (YELLOW): {len(yellow_tokens)}")
        report.append("-" * 40)
        for token in yellow_tokens:
            report.append(f"⚠️ {token}")
        
        report.append(f"\nHIGH RISK TOKENS (RED): {len(red_tokens)}")
        report.append("-" * 40)
        for token in red_tokens:
            report.append(f"🔴 {token}")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)

    async def run(self, scan_interval: int = SLEEP_INTERVAL, max_iterations: Optional[int] = None) -> None:
        """
        Run the scout bot main loop.
        
        Args:
            scan_interval: Time in seconds between scans
            max_iterations: Maximum number of scan iterations (None for infinite)
        """
        logger.info(f"Starting Solana Meme Scout Bot (scan interval: {scan_interval}s)")
        
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            iteration += 1
            logger.info(f"Starting scan iteration {iteration}")
            
            try:
                # Get recent token creations
                new_tokens = await self.get_recent_token_creations(limit=20)
                
                # Analyze new tokens
                for token_data in new_tokens:
                    token_address = token_data.get("token_address")
                    
                    # Skip if already tracked
                    if token_address in self.tracked_tokens:
                        continue
                        
                    # Analyze the token
                    analysis = await self.analyze_token(token_address)
                    
                    # Store token with analysis
                    token_data["analysis"] = analysis
                    self.tracked_tokens[token_address] = token_data
                    
                    logger.info(f"New token found: {token_data.get('metadata', {}).get('name')} " +
                                f"({token_data.get('metadata', {}).get('symbol')}) - " +
                                f"Risk: {analysis.get('risk_category', 'unknown')}")
                
                # Save tracked tokens to disk
                self.save_tracked_tokens()
                
                # Generate and log report every 5 iterations
                if iteration % 5 == 0:
                    report = self.generate_report()
                    logger.info("\n" + report)
                    
                    # Save report to file
                    with open(f"reports/report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w") as f:  # Updated path to match config
                        f.write(report)
                
                # Sleep until next iteration
                logger.info(f"Scan iteration {iteration} complete. Sleeping for {scan_interval} seconds...")
                await asyncio.sleep(scan_interval)
                
            except Exception as e:
                logger.error(f"Error in scan iteration {iteration}: {str(e)}")
                await asyncio.sleep(scan_interval)

async def main():
    """Main entry point for the Solana Meme Scout Bot."""
    bot = SolanaMemeScout()
    await bot.run()

if __name__ == "__main__":
    asyncio.run(main())