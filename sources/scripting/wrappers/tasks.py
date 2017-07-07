
import managers
from utils.threads import SmartThread
from utils.profiling import profiler


class Task(SmartThread):

    def __init__(self, *arguments, **keywords):
        self._application = None
        self._target = keywords.pop("target", None)
        if keywords.pop("daemon", False):
            self.daemon = True
        super(Task, self).__init__(*arguments, **keywords)

    def start(self):
        self._application = managers.engine.application
        super(Task, self).start()

    def main(self):
        if self._target:
            self._target()
        else:
            super(Task, self).main()

    def run(self):
        managers.engine.select(self._application)
        with profiler("tasks"):
            super(Task, self).run()
