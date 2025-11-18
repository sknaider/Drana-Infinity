"""
Drana-GTL Scan WebSocket Handler

Provides real-time updates for scan progress, findings, and status changes.
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from datetime import datetime
import websockets
from websockets.server import WebSocketServerProtocol

logger = logging.getLogger(__name__)


class DranaScanWebSocketHandler:
    """
    WebSocket handler for real-time Drana-GTL scan updates
    
    Provides:
    - Real-time scan progress updates
    - Finding notifications as they're discovered
    - Scan completion/failure notifications
    - Multi-client subscription management
    """
    
    def __init__(self):
        # Connected clients: {client_id: websocket}
        self.clients: Dict[str, WebSocketServerProtocol] = {}
        
        # Scan subscriptions: {scan_id: set of client_ids}
        self.scan_subscriptions: Dict[str, Set[str]] = {}
        
        # Client subscriptions: {client_id: set of scan_ids}
        self.client_scan_map: Dict[str, Set[str]] = {}
        
        logger.info("Drana Scan WebSocket Handler initialized")
    
    async def register(self, websocket: WebSocketServerProtocol, client_id: str):
        """Register a new WebSocket client"""
        self.clients[client_id] = websocket
        self.client_scan_map[client_id] = set()
        logger.info(f"Client registered: {client_id}")
        
        # Send welcome message
        await self.send_to_client(client_id, {
            "type": "connection_established",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def unregister(self, client_id: str):
        """Unregister a WebSocket client"""
        if client_id not in self.clients:
            return
        
        # Remove from all scan subscriptions
        scan_ids = self.client_scan_map.get(client_id, set())
        for scan_id in scan_ids:
            if scan_id in self.scan_subscriptions:
                self.scan_subscriptions[scan_id].discard(client_id)
                if not self.scan_subscriptions[scan_id]:
                    del self.scan_subscriptions[scan_id]
        
        # Remove client
        del self.clients[client_id]
        if client_id in self.client_scan_map:
            del self.client_scan_map[client_id]
        
        logger.info(f"Client unregistered: {client_id}")
    
    async def subscribe_to_scan(self, client_id: str, scan_id: str):
        """Subscribe a client to scan updates"""
        if client_id not in self.clients:
            logger.warning(f"Client {client_id} not found for subscription")
            return
        
        # Add to scan subscriptions
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(client_id)
        
        # Add to client map
        self.client_scan_map[client_id].add(scan_id)
        
        logger.info(f"Client {client_id} subscribed to scan {scan_id}")
        
        # Acknowledge subscription
        await self.send_to_client(client_id, {
            "type": "subscription_confirmed",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def unsubscribe_from_scan(self, client_id: str, scan_id: str):
        """Unsubscribe a client from scan updates"""
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(client_id)
            if not self.scan_subscriptions[scan_id]:
                del self.scan_subscriptions[scan_id]
        
        if client_id in self.client_scan_map:
            self.client_scan_map[client_id].discard(scan_id)
        
        logger.info(f"Client {client_id} unsubscribed from scan {scan_id}")
    
    async def send_to_client(self, client_id: str, message: Dict[str, Any]):
        """Send message to a specific client"""
        if client_id not in self.clients:
            return
        
        websocket = self.clients[client_id]
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            logger.warning(f"Connection closed for client {client_id}")
            await self.unregister(client_id)
        except Exception as e:
            logger.error(f"Error sending to client {client_id}: {e}")
    
    async def broadcast_scan_update(self, scan_id: str, update_data: Dict[str, Any]):
        """Broadcast scan update to all subscribed clients"""
        if scan_id not in self.scan_subscriptions:
            return
        
        message = {
            "type": "scan_update",
            "scan_id": scan_id,
            "data": update_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send to all subscribed clients
        tasks = []
        for client_id in self.scan_subscriptions[scan_id].copy():
            tasks.append(self.send_to_client(client_id, message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_progress_update(
        self,
        scan_id: str,
        progress: int,
        current_step: str,
        metadata: Optional[Dict] = None
    ):
        """Broadcast scan progress update"""
        update_data = {
            "progress": progress,
            "current_step": current_step,
            "metadata": metadata or {}
        }
        
        message = {
            "type": "progress_update",
            "scan_id": scan_id,
            "data": update_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if scan_id in self.scan_subscriptions:
            tasks = []
            for client_id in self.scan_subscriptions[scan_id].copy():
                tasks.append(self.send_to_client(client_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_finding_detected(
        self,
        scan_id: str,
        finding: Dict[str, Any]
    ):
        """Broadcast new finding detection"""
        message = {
            "type": "finding_detected",
            "scan_id": scan_id,
            "data": {
                "finding": finding
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if scan_id in self.scan_subscriptions:
            tasks = []
            for client_id in self.scan_subscriptions[scan_id].copy():
                tasks.append(self.send_to_client(client_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_scan_complete(
        self,
        scan_id: str,
        results: Dict[str, Any]
    ):
        """Broadcast scan completion"""
        message = {
            "type": "scan_complete",
            "scan_id": scan_id,
            "data": results,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if scan_id in self.scan_subscriptions:
            tasks = []
            for client_id in self.scan_subscriptions[scan_id].copy():
                tasks.append(self.send_to_client(client_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def broadcast_scan_failed(
        self,
        scan_id: str,
        error: str
    ):
        """Broadcast scan failure"""
        message = {
            "type": "scan_failed",
            "scan_id": scan_id,
            "data": {
                "error": error
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if scan_id in self.scan_subscriptions:
            tasks = []
            for client_id in self.scan_subscriptions[scan_id].copy():
                tasks.append(self.send_to_client(client_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def handle_client_message(self, client_id: str, message: str):
        """Handle incoming message from client"""
        try:
            data = json.loads(message)
            action = data.get("action")
            
            if action == "subscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    await self.subscribe_to_scan(client_id, scan_id)
            
            elif action == "unsubscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    await self.unsubscribe_from_scan(client_id, scan_id)
            
            elif action == "ping":
                await self.send_to_client(client_id, {
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            else:
                logger.warning(f"Unknown action from client {client_id}: {action}")
        
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from client {client_id}")
        except Exception as e:
            logger.error(f"Error handling message from client {client_id}: {e}")
    
    async def websocket_handler(self, websocket: WebSocketServerProtocol, path: str):
        """Main WebSocket connection handler"""
        # Generate client ID
        client_id = f"client_{id(websocket)}"
        
        try:
            # Register client
            await self.register(websocket, client_id)
            
            # Handle messages
            async for message in websocket:
                await self.handle_client_message(client_id, message)
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection closed for client {client_id}")
        except Exception as e:
            logger.error(f"Error in websocket handler for client {client_id}: {e}")
        finally:
            # Unregister client
            await self.unregister(client_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get handler statistics"""
        return {
            "total_clients": len(self.clients),
            "total_scan_subscriptions": len(self.scan_subscriptions),
            "scans_being_monitored": list(self.scan_subscriptions.keys()),
            "timestamp": datetime.utcnow().isoformat()
        }


# Global handler instance
_handler_instance: Optional[DranaScanWebSocketHandler] = None


def get_websocket_handler() -> DranaScanWebSocketHandler:
    """Get or create global WebSocket handler instance"""
    global _handler_instance
    if _handler_instance is None:
        _handler_instance = DranaScanWebSocketHandler()
    return _handler_instance


async def start_websocket_server(host: str = "0.0.0.0", port: int = 8765):
    """Start WebSocket server"""
    handler = get_websocket_handler()
    
    async with websockets.serve(handler.websocket_handler, host, port):
        logger.info(f"WebSocket server started on ws://{host}:{port}")
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(start_websocket_server())
