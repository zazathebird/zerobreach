namespace Scythe.TestKit;

public enum Endian
{
    Little,
    Big,
}

/// <summary>
/// What a length prefix counts. The two conventions differ per format and confusing them is a
/// real defect class (reference/17.1_builder.md): "Software" in UTF-16 is 8 characters and
/// 16 bytes.
/// </summary>
public enum LengthUnit
{
    Bytes,
    Characters,
}
