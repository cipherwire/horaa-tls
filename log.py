"""Central logging for horaa-tls.

Libraries MUST NOT configure handlers or emit bare print() calls.
Consumers control output via standard ``logging`` configuration::

    import logging
    logging.basicConfig(level=logging.INFO)          # see horaa-tls messages
    logging.getLogger("horaa_tls").setLevel(logging.DEBUG)  # verbose
"""
import logging

logger = logging.getLogger("horaa_tls")
