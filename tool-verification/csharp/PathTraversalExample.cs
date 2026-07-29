using System;
using System.IO;

class PathTraversalExample
{
    static void Main(string[] args)
    {
        string fileName = args[0];

        // Vulnerable: user input appended to a base path with no validation.
        string fullPath = "/var/www/files/" + fileName;
        string contents = File.ReadAllText(fullPath);

        Console.WriteLine(contents);
    }
}
