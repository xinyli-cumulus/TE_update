============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Always search the Jira tickets under the GSS project with the TE component
before any of the following:

Report Bugs
~~~~~~~~~~~

Report bugs in `Jira <https://tickets.cumulusnetworks.com/>`_

* Project: GSS
* Component: TE

If you are reporting a bug, please include:

* The operating system and version string.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.

Fix Bugs
~~~~~~~~

Tickets with type "bug" is open to whoever wants to implement it.

Implement Features
~~~~~~~~~~~~~~~~~~

Tickets with type "New Feature" or "Improvement" is open to whoever wants to
implement it.

Write Documentation
~~~~~~~~~~~~~~~~~~~

Turbo Entabulator could always use more documentation, whether as part of the
official TE documentation or the code docstrings.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file a ticket in Jira.

If you are proposing a feature:

* Explain in detail how it would work, including what commands or files the
  code would look at, to perform the desired analysis.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

Get Started!
------------

Ready to contribute? Here's how to set up `turbo-entabulator` for local
development.

#. Fork the `turbo-entabulator` repo on
   `Stash <https://stash.cumulusnetworks.com/projects/DEVTOOLS/repos/turbo-entabulator?fork>`_

#. Clone your fork locally:

    $ git clone ssh://git@stash.cumulusnetworks.com:7999/~<username>/turbo-entabulator.git

#. Install your local copy into a virtualenv. Assuming you have
   virtualenvwrapper installed (if not you are missing out), this is how you
   set up your fork for local development::

    $ mkvirtualenv turbo-entabulator
    $ cd turbo-entabulator/
    $ pip install -r requirements.txt
    $ python setup.py develop

#. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

#. Now you can make your code changes locally, and be sure to follow the python
   `PEP8 <https://pep8.readthedocs.io/en/release-1.7.x/intro.html>`_ code
   style, as well as the Coding Guidelines below.

#. When you're done making changes, check that your changes pass flake8 and the
   tests, including testing other Python versions with tox::

    $ flake8 turbo_entabulator tests
    $ python setup.py test
    $ tox

#. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

#. Submit a pull request through the stash UI.

Coding Guidelines
-----------------

To maintain consistency and quality of code, additions to turbo_entabulator
must adhere to the following criteria to be accepted:

* All discovery of information must be done within a discovery function.
* All detection of issues must be done within a detection function.
* Any function that is not a discovery or detection is deemed a utility
  function.

.. note:: The exception to the above rules is `detect_log_sigs`, wherein all
 log files are analized for log signatures.  There is no reason to store the
 complete contents of all log files in a discovery function for later
 analysis in a detection function.

* Discovery functions must be contained within discovery.py and must be
  placed within that file in alphabetical order of existing functions.
* Detection functions must be contained within detections.py and must be placed
  within that file in alphabetical order of existing functions.
* All utility functions must be contained within utilities.py and must be
  placed within that file in alphabetical order of existing functions.
* No line of code should exceed 79 characters in width.  Some exceptions may be
  made for certain code that can not be split into multiple lines.

* All functions must use the following template::

    def example_function(deprecated, satisfied, some_other):
        # Example Format of discovery / detection functions.
        # All detection functions need to
        # follow this format and must include a description at the beginning of the
        # function describing the purpose of the function.  The boilerplate code
        # shown in this example must be included.
        name = sys._getframe().f_code.co_name
        logger.debug("This is {}().".format(name))
        if name in deprecated:
            logger.debug("[{}] is deprecated. Skipping".format(name))
            return(satisfied, some_other)
        reqs = ['list', 'of', 'prerequesite', 'functions']
        if not check_dependencies(name, reqs, satisfied):
            return(satisfied, others)
        # Discovery, Detection or Utility code goes here...
        #
        # Any failure should return(satisfied) [and any other structures as
        # necessary].
        #
        # If the function completes safely, append the function name to list
        # satisfied:
        satisfied.append(name)
        # Then, return:
        return(satisfied, some_other)


* All functions need deprecated and satisfied to be passed to them. This allows
  the function to check if it has been deprecated (should not run), as
  well as if relevant pre-requesite functions have completed successfully.
  For example, function discover_bridges requires information previously
  discovered in discover_ifquery.  Subsequently, 'discover_ifquery' is
  included in reqs.


Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.
3. The pull request should pass the Continuous Integration tests
   and make sure that all tests pass. You can run the tests locally
   using `tox`.

Tips
----

To create a source distribution of this pip package::

    $ python setup.py build
