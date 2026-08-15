class SAMLVerifier:
    def verify(self, xml_text: str, config: dict, now: int) -> dict:
        raise NotImplementedError
