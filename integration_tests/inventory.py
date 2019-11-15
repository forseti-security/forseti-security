import pytest
import sh


class TestInventory:
    @pytest.mark.integration_test
    @pytest.mark.inventory
    def test_inventory_create(self):
        output = sh.forseti('inventory', 'create')
        assert output.exit_code == 0
