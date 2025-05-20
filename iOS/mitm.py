#!/usr/bin/env python
"""
A mitmproxy plugin that dumps HTTP requests and responses to files in Burp-like format.
Usage: mitmdump -s burp_style_dump.py

Options:
- dump_folder: Directory to save HTTP dump files (default: ./http_dump)
- req_resp_format: Format for saving files (default: both) - options: both, request, response
- filter_str: Filter expression for which flows to save (default: "" - save all)

Example usage with filter:
mitmdump -s burp_style_dump.py --set filter_str="~d secure.wf.com"
"""

import os
import time
import datetime
from pathlib import Path
from typing import Optional, Tuple

from mitmproxy import ctx, http, flowfilter


class BurpStyleDump:
    def __init__(self):
        self.filter = None
        self.num_flows = 0

    def load(self, loader):
        loader.add_option(
            name="dump_folder",
            typespec=str,
            default="http_dump",
            help="Directory to save HTTP dump files",
        )
        loader.add_option(
            name="req_resp_format",
            typespec=str,
            default="both",
            help="Format for saving files (both, request, response)",
        )
        loader.add_option(
            name="filter_str",
            typespec=str,
            default="",
            help="Filter expression for flows to save",
        )

    def configure(self, updated):
        if "filter_str" in updated and ctx.options.filter_str:
            self.filter = flowfilter.parse(ctx.options.filter_str)
            ctx.log.info(f"Filter configured: {ctx.options.filter_str}")
        
        # Create dump folder if it doesn't exist
        dump_path = Path(ctx.options.dump_folder)
        if not dump_path.exists():
            os.makedirs(dump_path)
            ctx.log.info(f"Created dump folder: {dump_path}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Skip if filter doesn't match
        if self.filter and not flowfilter.match(self.filter, flow):
            return
        
        # Only process completed flows with responses
        if not flow.response:
            return

        self.num_flows += 1
        self.save_flow(flow)

    def format_headers(self, headers) -> str:
        """Format headers dictionary into string format"""
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    def format_request(self, flow: http.HTTPFlow) -> str:
        """Format the request in a Burp-like format"""
        req = flow.request
        host = req.headers.get("Host", req.host)
        
        # First line: METHOD PATH HTTP/VERSION
        first_line = f"{req.method} {req.path} {req.http_version}"
        
        # Headers
        headers_str = self.format_headers(req.headers)
        
        # Put it all together
        result = f"{first_line}\n{headers_str}"
        
        # Add body if present
        if req.content:
            result += f"\n\n{req.content.decode('utf-8', errors='replace')}"
        
        return result

    def format_response(self, flow: http.HTTPFlow) -> str:
        """Format the response in a Burp-like format"""
        resp = flow.response
        
        # First line: HTTP/VERSION STATUS_CODE STATUS_TEXT
        first_line = f"{flow.request.http_version} {resp.status_code} {resp.reason}"
        
        # Headers
        headers_str = self.format_headers(resp.headers)
        
        # Put it all together
        result = f"{first_line}\n{headers_str}"
        
        # Add body if present
        if resp.content:
            try:
                body = resp.content.decode('utf-8', errors='replace')
                result += f"\n\n{body}"
            except Exception as e:
                result += f"\n\n[Binary content not displayed: {e}]"
        
        return result

    def get_filename(self, flow: http.HTTPFlow) -> Tuple[str, str]:
        """Generate a descriptive filename for the flow"""
        timestamp = datetime.datetime.fromtimestamp(flow.request.timestamp_start).strftime("%Y%m%d_%H%M%S")
        host = flow.request.host.replace(":", "_")
        method = flow.request.method
        path = flow.request.path.replace("/", "_")[:50]  # Limit path length in filename
        status = flow.response.status_code if flow.response else "incomplete"
        
        # Make sure filename is valid
        base_name = f"{timestamp}_{host}_{method}_{path}_{status}_{flow.id}"
        base_name = "".join(c for c in base_name if c.isalnum() or c in "_-.")[:200]  # Sanitize and limit length
        
        req_name = f"{base_name}.req"
        resp_name = f"{base_name}.resp"
        
        return req_name, resp_name

    def save_flow(self, flow: http.HTTPFlow) -> None:
        """Save the flow to files"""
        dump_folder = Path(ctx.options.dump_folder)
        req_filename, resp_filename = self.get_filename(flow)
        format_type = ctx.options.req_resp_format
        
        # Save request
        if format_type in ["both", "request"]:
            req_path = dump_folder / req_filename
            with open(req_path, "w", encoding="utf-8") as f:
                f.write(self.format_request(flow))
            ctx.log.info(f"Saved request: {req_path}")
        
        # Save response
        if format_type in ["both", "response"] and flow.response:
            resp_path = dump_folder / resp_filename
            with open(resp_path, "w", encoding="utf-8") as f:
                f.write(self.format_response(flow))
            ctx.log.info(f"Saved response: {resp_path}")

    def done(self):
        ctx.log.info(f"Session complete. Saved {self.num_flows} flows to {ctx.options.dump_folder}")


addons = [BurpStyleDump()]
