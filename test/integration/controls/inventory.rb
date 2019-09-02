require 'json'
control 'inventory' do

    describe "Inventory create command are automated" do
        subject do
            command("forseti inventory list")
        end
        before do
            command("forseti inventory create").result
        end
        its("stdout") { should match /SUCCESS/}
        its("stderr") { should eq ""}
        after do
            command("forseti inventory purge 0").result
        end
    end
end