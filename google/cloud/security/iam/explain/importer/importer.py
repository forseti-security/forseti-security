
import forseti

class ForsetiImporter:
    def __init__(self, session, model):
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer()

    def run(self):
        self.model.set_inprogress(self.session)
        self.model.kick_watchdog(self.session)

        for obj in self.forseti_importer:
            print obj
            self.model.kick_watchdog(self.session)
            
        self.model.set_done(self.session)
        import code
        code.interact(local=locals())