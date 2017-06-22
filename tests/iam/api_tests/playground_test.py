
from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ApiTestRunner, create_test_engine, cleanup
from tests.unittest_utils import ForsetiTestCase


class TestServiceConfig(object):
    """ServiceConfig Stub."""
    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)

    def run_in_background(self, function):
        """Stub."""
        function()
        return self


def create_tester():
    """Create API test runner."""
    return ApiTestRunner(
        TestServiceConfig(),
        [GrpcExplainerFactory,
         GrpcPlaygrounderFactory])


class ApiTest(ForsetiTestCase):
    """Api Test."""

    def setUp(self):
        self.setup = create_tester()

    def has_no_models(self, client):
        """Returns true iff the server has no model."""
        return self.has_n_models(client, 0)

    def has_n_models(self, client, number):
        """Returns true iff the server has n models."""
        return len(client.list_models().models) == number

    def test_create_empty_model_and_delete(self):
        """Test: Create empty model, then delete again."""
        def test(client):
            """API test callback."""
            self.assertEquals(
                len(client.list_models().models),
                0,
                'Expect no previous models')
            model1 = client.new_model("EMPTY", name='model1').model.handle
            model2 = client.new_model("EMPTY", name='model2').model.handle

            self.assertTrue(self.has_n_models(client, 2))
            client.delete_model(model1)
            self.assertTrue(self.has_n_models(client, 1))
            client.delete_model(model2)
            self.assertTrue(self.has_no_models(client))

        self.setup.run(test)

    def test_create_empty_model(self):
        """Test: create and empty model."""
        @cleanup
        def test(client):
            """API test callback."""
            self.assertEqual(
                [m.handle for m in client.list_models().models],
                [],
                'Expect no previous models')
            client.new_model('EMPTY', 'test_model')
            self.assertTrue(
                self.has_n_models(client, 1),
                'One model must be created')

        self.setup.run(test)

    def test_create_and_list_members(self):
        """Test: create and list members."""
        @cleanup
        def test(client):
            """API test callback."""
            reply = client.new_model('EMPTY', name='test1')
            client.switch_model(reply.model.handle)
            self.assertEqual(
                len(client.playground.list_members("").member_names),
                0,
                'Expect no members in the empty model')
            client.playground.add_member('user/user1')
            self.assertEqual(
                len(client.playground.list_members("").member_names),
                1,
                'Expect one members in the empty model')
            client.playground.add_member('group/group1')
            self.assertEqual(
                len(client.playground.list_members("").member_names),
                2,
                'Expect two members in the empty model')
            client.playground.add_member('user/user2', ['group/group1'])
            self.assertEqual(
                len(client.playground.list_members("").member_names),
                3,
                'Expect three members in the empty model')
            self.assertEqual(
                len(client.playground.list_members("user").member_names),
                2)
            self.assertEqual(
                len(client.playground.list_members("group").member_names),
                1)
            client.playground.del_member('user/user1')
            self.assertEqual(
                len(client.playground.list_members("user").member_names),
                1)
            self.assertEqual(
                len(client.playground.list_members("group").member_names),
                1)
            client.playground.del_member('group/group1')
            client.playground.del_member('user/user2')
            self.assertEqual(
                len(client.playground.list_members("").member_names),
                0,
                'Expect no members in the empty model')

        self.setup.run(test)
