from google.cloud.forseti.common.util.email import email_factory


empty_notifier_config = {}

half_filled = {asdasdasdasd}

class EmailFactoryTest():


    """
    1. create fake notifier config for diff scenarios
        - assuming if all the email connector config are filled out
        - assuming it's half filled
        - assuming its empty
        - assuming email connector is not there

    2. create 4 unit tests
        each for the corresponding cases listed above


        def test_empty_notifier_config()
            EU = EmailFactory(empty_notifier_config)

            result = EU.get_connector()

            assset expected_result, result


    """