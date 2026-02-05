using System.Text;

namespace SocketServer
{
    internal static class BytePattern
    {
        internal static byte[] ReplacePattern(byte[] sourceBytes, byte[] patternToFind, byte[] patternToReplace)
        {
            if (sourceBytes == null)
                throw new ArgumentNullException(nameof(sourceBytes), "Le tableau source ne peut pas être null.");
            if (patternToFind == null)
                throw new ArgumentNullException(nameof(patternToFind), "Le pattern à rechercher ne peut pas être null.");
            if (patternToReplace == null)
                throw new ArgumentNullException(nameof(patternToReplace), "Le pattern de remplacement ne peut pas être null.");
            if (patternToFind.Length == 0)
                throw new ArgumentException("Le pattern à rechercher ne peut pas être vide.", nameof(patternToFind));
            if (patternToFind.Length != patternToReplace.Length)
                throw new ArgumentException("Le pattern à rechercher et le pattern de remplacement doivent avoir la même taille.");

            byte[] result = sourceBytes.ToArray();

            // Taille du pattern
            int patternSize = patternToFind.Length;

            List<int> occurrences = FindAllOccurrences(sourceBytes, patternToFind);

            foreach (int index in occurrences)
            {
                for (int i = 0; i < patternSize; i++)
                {
                    result[index + i] = patternToReplace[i];
                }
            }

            return result;
        }

        private static List<int> FindAllOccurrences(byte[] sourceBytes, byte[] pattern)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int maxPosition = sourceBytes.Length - patternLength;

            for (int i = 0; i <= maxPosition; i++)
            {
                bool found = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (sourceBytes[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    positions.Add(i);
                    // Si on souhaite éviter les chevauchements de patterns, on peut décommenter la ligne suivante
                    // i += patternLength - 1;
                }
            }

            return positions;
        }

        internal static byte[] ReplacePatternWithSize(byte[] sourceBytes, byte[] patternToFind, byte[] patternToReplace, int patternSize)
        {
            // Vérification que les patterns ont bien la taille spécifiée
            if (patternToFind.Length != patternSize)
                throw new ArgumentException($"Le pattern à rechercher doit avoir une taille de {patternSize} octets.");
            if (patternToReplace.Length != patternSize)
                throw new ArgumentException($"Le pattern de remplacement doit avoir une taille de {patternSize} octets.");

            // Appel à la méthode principale
            return ReplacePattern(sourceBytes, patternToFind, patternToReplace);
        }


        internal static string FormatByteArrayToHex(byte[] bytes, int bytesPerLine = 16, bool showOffset = true, bool showAscii = true)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes), "Le tableau d'octets ne peut pas être null.");

            if (bytesPerLine <= 0)
                throw new ArgumentOutOfRangeException(nameof(bytesPerLine), "Le nombre d'octets par ligne doit être positif.");

            if (bytes.Length == 0)
                return "Tableau vide";

            StringBuilder result = new StringBuilder();

            for (int i = 0; i < bytes.Length; i += bytesPerLine)
            {
                if (showOffset)
                {
                    result.Append($"{i:X8}: ");
                }

                StringBuilder hexPart = new StringBuilder();
                StringBuilder asciiPart = new StringBuilder();

                int lineLength = Math.Min(bytesPerLine, bytes.Length - i);

                for (int j = 0; j < lineLength; j++)
                {
                    byte b = bytes[i + j];

                    hexPart.Append($"{b:X2} ");
                    if (showAscii)
                    {
                        if (b >= 32 && b <= 126)
                        {
                            asciiPart.Append((char)b);
                        }
                        else
                        {
                            asciiPart.Append('.');
                        }
                    }
                }

                if (showAscii && lineLength < bytesPerLine)
                {
                    hexPart.Append(new string(' ', (bytesPerLine - lineLength) * 3));
                }

                result.Append(hexPart);

                if (showAscii)
                {
                    result.Append(" | ");
                    result.Append(asciiPart);
                }

                if (i + bytesPerLine < bytes.Length)
                {
                    result.AppendLine();
                }
            }

            return result.ToString();
        }

        public static string FormatByteArrayToHexUnicode(byte[] bytes, int bytesPerLine = 16, bool showOffset = true,
            bool showText = true, Encoding encoding = null)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes), "Le tableau d'octets ne peut pas être null.");

            if (bytesPerLine <= 0)
                throw new ArgumentOutOfRangeException(nameof(bytesPerLine), "Le nombre d'octets par ligne doit être positif.");

            if (bytes.Length == 0)
                return "Tableau vide";

            // Si aucun encodage n'est spécifié, utiliser UTF-8 par défaut
            encoding = encoding ?? Encoding.UTF8;

            StringBuilder result = new StringBuilder();

            // Nous avons besoin de traiter les octets par blocs pour l'encodage Unicode
            // Surtout pour UTF-8 où un caractère peut être codé sur plusieurs octets
            for (int i = 0; i < bytes.Length; i += bytesPerLine)
            {
                // Afficher l'offset au début de la ligne
                if (showOffset)
                {
                    result.Append($"{i:X8}: ");
                }

                // Partie hexadécimale
                StringBuilder hexPart = new StringBuilder();

                // Nombre d'octets à traiter sur cette ligne
                int lineLength = Math.Min(bytesPerLine, bytes.Length - i);

                // Ajout de la partie hexadécimale
                for (int j = 0; j < lineLength; j++)
                {
                    byte b = bytes[i + j];
                    hexPart.Append($"{b:X2} ");
                }

                // Compléter avec des espaces pour aligner la partie texte
                if (showText && lineLength < bytesPerLine)
                {
                    hexPart.Append(new string(' ', (bytesPerLine - lineLength) * 3));
                }

                // Ajouter la partie hexadécimale
                result.Append(hexPart);

                // Ajouter la partie texte en Unicode si nécessaire
                if (showText)
                {
                    result.Append(" | ");

                    // Extraire le bloc d'octets pour cette ligne
                    byte[] lineBytes = new byte[lineLength];
                    Array.Copy(bytes, i, lineBytes, 0, lineLength);

                    // Décodage des octets selon l'encodage spécifié
                    try
                    {
                        // Décoder les octets en caractères selon l'encodage
                        string decodedText = encoding.GetString(lineBytes);

                        // Remplacer les caractères de contrôle par des points
                        StringBuilder cleanText = new StringBuilder();
                        foreach (char c in decodedText)
                        {
                            if (char.IsControl(c) || c == '\t' || c == '\r' || c == '\n')
                            {
                                cleanText.Append('.');
                            }
                            else
                            {
                                cleanText.Append(c);
                            }
                        }

                        result.Append(cleanText);
                    }
                    catch (DecoderFallbackException)
                    {
                        // En cas d'erreur de décodage, afficher des points
                        result.Append(new string('.', lineLength));
                    }
                }

                // Nouvelle ligne (sauf pour la dernière ligne)
                if (i + bytesPerLine < bytes.Length)
                {
                    result.AppendLine();
                }
            }

            return result.ToString();
        }

        internal static string ByteArrayToHexString(byte[] bytes, string separator = " ")
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes), "Le tableau d'octets ne peut pas être null.");

            if (bytes.Length == 0)
                return string.Empty;

            StringBuilder hex = new StringBuilder(bytes.Length * (2 + separator.Length));

            for (int i = 0; i < bytes.Length; i++)
            {
                hex.AppendFormat("{0:X2}", bytes[i]);

                if (i < bytes.Length - 1)
                {
                    hex.Append(separator);
                }
            }

            return hex.ToString();
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

    }
}