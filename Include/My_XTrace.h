
/// <summary>
/// printf() style messaging
/// https://stackoverflow.com/questions/15240/
/// </summary>
/// <param name="bufferReturned">pointer to a 512 WORDs array </param>
/// <param name="lpszFormat">-Debugging text</param>
/// <param name="">.... parameters in _vstprintf_s() style</param>
void XTrace0(LPCTSTR lpszText)
{
    ::OutputDebugString(lpszText);
}

/// <summary>
/// printf() style messaging
/// https://stackoverflow.com/questions/15240/
/// </summary>
/// <param name="bufferReturned">pointer to a 512 WORDs array </param>
/// <param name="lpszFormat">-Debugging text</param>
/// <param name="">.... parameters in _vstprintf_s() style</param>
void XTrace(LPCTSTR lpszFormat, ...)
{
    va_list args;
    va_start(args, lpszFormat);
    int nBuf;
    TCHAR szBuffer[512]; 
    nBuf = _vstprintf_s(szBuffer, 511, lpszFormat, args);
    ::OutputDebugString(szBuffer);
    va_end(args);
}

/// <summary>
/// printf() style messaging
/// https://stackoverflow.com/questions/15240/
/// </summary>
/// <param name="bufferReturned">pointer to a 512 WORDs array </param>
/// <param name="lpszFormat">-Debugging text</param>
/// <param name="">.... parameters in _vstprintf_s() style</param>
wchar_t* MessageFormated(wchar_t* bufferReturned, LPCTSTR lpszFormat, ...)
{
    va_list args;
    va_start(args, lpszFormat);
    int nBuf;
    nBuf = _vstprintf_s(bufferReturned, 511, lpszFormat, args);
    //::OutputDebugString(szBuffer);
    va_end(args);
    return bufferReturned;
}