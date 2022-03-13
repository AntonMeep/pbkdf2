pragma Ada_2012;

with Interfaces;

package body PBKDF2 is
  function Write_Big_Endian(Input : Stream_Element_Offset) return Stream_Element_Array is
    use Interfaces;

    Int : constant Unsigned_32 := Unsigned_32(Input);
  begin
    return (
      0 => Stream_Element(Shift_Right(Int, 24) and 16#FF#),
      1 => Stream_Element(Shift_Right(Int, 16) and 16#FF#),
      2 => Stream_Element(Shift_Right(Int, 8) and 16#FF#),
      3 => Stream_Element(Int and 16#FF#)
    );
  end Write_Big_Endian;

  function F(Password       : String; Salt : String; Iterations : Natural;
      I : Stream_Element_Offset) return Stream_Element_Array is
      
      use GNAT.SHA1;
      Result : Binary_Message_Digest;
      Last : Binary_Message_Digest;
      Ctx : Context;
    begin
      --  First iteration
      Ctx := HMAC_Initial_Context(Password);
      Update(Ctx, Salt);
      Update(Ctx, Write_Big_Endian(I));
      Result := Digest(Ctx);
      Last := Result;

      --  Subsequent iterations
      for J in 2..Iterations loop
        Ctx := HMAC_Initial_Context(Password);
        Update(Ctx, Last);
        Last := Digest(Ctx);
        for L in Result'Range loop
          Result(L) := Result(L) xor Last(L);
        end loop;
      end loop;
      return Result;
    end F;

   function PBKDF2_HMAC_SHA1
     (Password       : String; Salt : String; Iterations : Natural;
      Derived_Length : Stream_Element_Offset := GNAT.SHA1.Hash_Length)
      return Stream_Element_Array
   is
    use GNAT.SHA1;

    Result : Stream_Element_Array(1 .. Derived_Length) := (others => 0);
    Current : Stream_Element_Offset := Result'First;

    Blocks_Needed : Stream_Element_Offset :=
      Stream_Element_Offset(Float'Ceiling(Float(Derived_Length) / Float(Hash_Length)));
    
   begin
      for I in 1..Blocks_Needed loop
        Result(Current .. Current + Hash_Length) := F(Password, Salt, Iterations, I);
        Current := Current + Hash_Length;
      end loop;
      
      return Result;
   end PBKDF2_HMAC_SHA1;

end PBKDF2;
