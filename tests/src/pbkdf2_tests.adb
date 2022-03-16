with AUnit.Reporter.Text;
with AUnit.Run;

with PBKDF2.Tests;

procedure PBKDF2_Tests is
   procedure Runner is new AUnit.Run.Test_Runner (PBKDF2.Tests.Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Reporter.Set_Use_ANSI_Colors (True);
   Runner (Reporter);
end PBKDF2_Tests;
